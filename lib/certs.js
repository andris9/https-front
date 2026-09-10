'use strict';

// Certificate provisioning. The ACME protocol, the certificate store and the
// renewal schedule all live in @postalsys/certs; what stays here is the domain
// validation this proxy does before it is willing to order anything, and the
// decision of what to serve while an order is running.

const crypto = require('crypto');
const { Certs, isRenewalDue } = require('@postalsys/certs');
const config = require('@zone-eu/wild-config');
const psl = require('psl');
const { Resolver } = require('dns').promises;
const resolver = new Resolver();

const { redisClient } = require('./db');
const { coalesce, normalizeDomain, unicodeDomain, isValidDomain } = require('./tools');
const { checkUrl } = require('./check-url');
const { importAccount, importCertificate } = require('./legacy-certs');
const { spendToken, blockWithBackoff, blockBriefly, areBlocked, isBlocked, clearBlock } = require('./rate-limit');

const { componentLogger } = require('./logger');
const logger = componentLogger('certs');

if (config?.resolver?.ns?.length) {
    resolver.setServers([].concat(config.resolver.ns || []));
}

// Blocked for this long after an attempt fails, whether the domain did not
// validate or the order itself did not go through. The store keeps a failsafe
// lock of its own underneath, and a longer one; this is what stops the DNS
// queries and the validation request behind validateDomain from being repeated
// on every handshake, and it is short enough that a domain whose DNS was just
// corrected is picked up quickly.
//
// It doubles for each consecutive failure, up to the hour the store's own lock
// lasts. A name that is never going to validate, which is most of what a
// scanner working through a list of domains asks for, otherwise costs three DNS
// queries and a checkUrl request every five minutes for as long as the traffic
// lasts, and there is no number of them that makes the next attempt any more
// likely to succeed.
const BLOCK_RENEW_AFTER_FAILURE_TTL = 300;
const BLOCK_RENEW_MAX_TTL = 3600;

// How long past the longest block a run of failures is still remembered, so a
// domain that has come good starts again from the shortest one.
const BLOCK_FAILURE_MEMORY_TTL = 3600;

// Turned away by a budget rather than by anything wrong with the domain, so it
// is held only long enough that the next handshake does not ask again at once.
// Deliberately not counted as a failure: a domain waiting its turn must not
// escalate the way one that cannot be validated at all does.
const BLOCK_NO_BUDGET_TTL = 60;

const CAA_DOMAIN = 'letsencrypt.org';

// What a certificate authority answers with once the account is over a limit.
// RFC 8555 section 6.7.
const RATE_LIMITED = 'urn:ietf:params:acme:error:rateLimited';

// What each of these means, and why it is set where it is, is documented once in
// config/default.toml, which is always merged underneath whatever else is
// configured. These are the fallback for an installation pointed at a
// configuration directory of its own, where that file is not there to be merged:
// without them an unset budget reads as no budget at all, which is the one
// answer this module must never give.
const LIMIT_DEFAULTS = {
    ordersPerHour: 90,
    orderBurst: 30,
    validationsPerMinute: 600,
    validationBurst: 100,
    renewalReserve: 0.5,
    pauseBase: 900,
    pauseMax: 10800
};

const limits = () => Object.assign({}, LIMIT_DEFAULTS, config?.acme?.limits);

// Everything this instance stores lives under this prefix, which keeps a staging
// pool and a production pool apart in one Redis database the way the
// `acme:certificate:<key>:*` keys of earlier releases did.
const NAMESPACE = `acme:${config.acme.key}`;

// The one place the prefix is spelled, so that lib/renewal-sweeper.js names its
// lease the same way this module names everything else.
const poolKey = name => `${NAMESPACE}:${name}`;

// The certificate store, built on first use rather than at load time: it opens a
// second Redis connection for the renewal lock, and a worker that never sees a
// TLS handshake has no use for either.
let instance = null;
const getCerts = () => {
    if (!instance) {
        instance = new Certs({
            redis: redisClient,
            namespace: NAMESPACE,

            // P-256 rather than RSA: everything this proxy terminates is browser
            // traffic, where EC is universally supported, and a smaller key makes
            // for a cheaper handshake. A certificate carried over from an earlier
            // release keeps the RSA key it was issued with, because the key and
            // the certificate have to match.
            keyType: 'ec',

            acme: {
                // Only names the ACME account entry, and the namespace above
                // already keeps the pools apart, but it keeps a staging account
                // from being read back as a production one.
                environment: config.acme.key,
                directoryUrl: config.acme.directoryUrl,
                email: config.acme.email,

                // CAA is checked in validateDomain() below instead. The store
                // resolves with the system resolver, and this proxy has to honour
                // `resolver.ns`, so the check would otherwise be made twice and
                // answered by two different servers.
                caaDomains: []
            },

            logger: componentLogger('acme')
        });
    }
    return instance;
};

// Marks a domain whose last attempt failed, and the count of how many times in a
// row it has. Keyed the way every other name in this module is, which is not how
// the store spells its own keys, so this stays this module's own bookkeeping
// rather than a guess at the store's.
const blockKey = domain => poolKey(`blocked:${domain}`);
const failureKey = domain => poolKey(`failures:${domain}`);

// One pause and one pair of budgets for the whole pool, because what they stand
// in for is counted per ACME account and the pool is what holds the account.
const pauseKey = () => poolKey('paused');
const pauseFailureKey = () => poolKey('paused:failures');
const budgetKey = name => poolKey(`budget:${name}`);

// Tokens for the DNS queries and the validation request in validateDomain. That
// is the expensive half of an attempt and the half a flood reaches first: a name
// that was never pointed here fails validation and never costs an order, but it
// costs three DNS queries and a checkUrl request every time it is asked for.
const spendValidation = ({ renewal } = {}) => {
    const { validationsPerMinute, validationBurst, renewalReserve } = limits();
    return spendToken({
        key: budgetKey('validations'),
        capacity: validationBurst,
        refillPerSecond: validationsPerMinute / 60,
        floor: renewal ? 0 : validationBurst * renewalReserve
    });
};

// Tokens for the order itself, which is the one the certificate authority counts
// and the one there is no getting more of.
const spendOrder = ({ renewal, cost = 1 } = {}) => {
    const { ordersPerHour, orderBurst, renewalReserve } = limits();
    return spendToken({
        key: budgetKey('orders'),
        capacity: orderBurst,
        refillPerSecond: ordersPerHour / 3600,
        cost,
        floor: renewal ? 0 : orderBurst * renewalReserve
    });
};

// What is left of the order budget, without spending any of it, so that a
// renewal pass can tell whether it is worth reading records it could not act on.
const orderBudget = async () => (await spendOrder({ renewal: true, cost: 0 })).tokens;

// A rate limit is not something one domain ran into. The certificate authority
// counts orders per account, so it is the whole pool that is out of budget, and
// every other domain that goes on to order only spends another request finding
// that out. That is what keeps an account pinned at its limit rather than
// recovering from it, so the pool stops together and comes back together.
//
// The pause is timed here rather than from the `Retry-After` the CA sent: the
// ACME client caps that at a minute before it reaches us, because it also uses
// it as a polling delay, so what arrives says nothing about how long the limit
// has left to run.
const pauseOrders = async err => {
    const { pauseBase, pauseMax } = limits();
    const { failures, ttl } = await blockWithBackoff({
        key: pauseKey(),
        counterKey: pauseFailureKey(),
        base: pauseBase,
        max: pauseMax,
        memory: pauseMax
    });
    logger.error({ msg: 'Orders paused, the ACME account is rate limited', failures, ttl, err });
};

const ordersPaused = () => isBlocked(pauseKey());

// An order that went through says the account is not over a limit, so the next
// pause starts from the base again rather than from wherever the last run of
// them escalated to. Only the count is cleared: an order that was already in
// flight when another worker armed the pause says nothing about the moment it
// was armed for, so the pause itself is left to expire on its own.
const clearPauseBackoff = () => clearBlock({ counterKey: pauseFailureKey() });

// An error the certificate authority answered with, rather than one raised on
// the way to it. The store arms its own hour long failsafe lock for exactly
// these, so nothing is going to be ordered for the domain within the hour
// whatever this module decides. Matching that straight away, instead of
// escalating towards it, is what keeps validateDomain from running another
// eleven times inside an hour the store has already written off.
const isCaError = err => typeof err?.type === 'string' && err.type.startsWith('urn:ietf:params:acme:');

const blockRenewal = async (domain, err) => {
    // Recorded in Redis rather than in the worker, so that every worker and
    // every instance sharing this certificate pool backs off too. A CA answered
    // error starts at the cap rather than doubling towards it, which is what
    // stops the doubling from disagreeing with the store's own lock.
    const { failures, ttl } = await blockWithBackoff({
        key: blockKey(domain),
        counterKey: failureKey(domain),
        base: isCaError(err) ? BLOCK_RENEW_MAX_TTL : BLOCK_RENEW_AFTER_FAILURE_TTL,
        max: BLOCK_RENEW_MAX_TTL,
        memory: BLOCK_FAILURE_MEMORY_TTL
    });
    logger.info({ msg: 'Renewal blocked after a failure', domain, failures, ttl });
};

// Everything a failed order costs, in one place: the pool stops if the account
// is over a limit, and the domain backs off either way. Reached both from the
// error the store threw and from the one it reported instead of throwing. The
// caller clears `pause` for a failure it knows the account was not answered with
// just now, which the domain still has to back off from but the pool does not.
const recordFailure = async (domain, err, { pause = true } = {}) => {
    if (pause && err?.type === RATE_LIMITED) {
        await pauseOrders(err);
    }
    await blockRenewal(domain, err);
};

// Everything this domain was backing off from is over.
const clearRenewalBlock = domain => clearBlock({ key: blockKey(domain), counterKey: failureKey(domain) });

// True while the stored certificate can still be served. A renewal that can not
// be attempted leaves the current certificate in place, but an expired one is
// never handed back, and neither is the key-only record an order in flight
// leaves behind. An unreadable expiry compares false, which is the answer that
// keeps the SNI handler on the default certificate.
const isUsable = certificateData =>
    Boolean(certificateData && certificateData.cert && certificateData.privateKey && new Date(certificateData.validTo).getTime() > Date.now());

const validateDomain = async domain => {
    // The name as a person reads it. Every error thrown here ends up in a log
    // line or an operator's hands, and those spell a domain the way lib/logger.js
    // does; the A-label stays in the `domain` field of the entry.
    const name = unicodeDomain(domain);

    // check domain name format
    if (!isValidDomain(domain)) {
        // invalid domain name, can not create certificate
        let err = new Error(`${name} is not a valid domain name`);
        err.code = 'invalid_domain';
        throw err;
    }

    // check the CAA records, walking up the labels until one is found
    let parts = domain.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
        let subdomain = parts.slice(i).join('.');
        let caaRes;
        try {
            caaRes = await resolver.resolveCaa(subdomain);
        } catch (err) {
            // assume not found
        }
        if (caaRes?.length && !caaRes.some(r => (r?.issue || '').trim().toLowerCase() === CAA_DOMAIN)) {
            let err = new Error(`LE not listed in the CAA record for ${unicodeDomain(subdomain)} (${name})`);
            err.code = 'caa_mismatch';
            throw err;
        } else if (caaRes?.length) {
            logger.info({ msg: 'Found matching CAA record', subdomain, domain });
            break;
        }
    }

    // resolve random domain to detect wildcard records
    if (!config?.extraChecks?.wildCardAllowed) {
        try {
            let mainDomain = psl.get(domain) || domain;
            if (mainDomain !== domain) {
                let altDomain = domain.replace(/^[^.]+\./, `${crypto.randomBytes(8).toString('hex')}.`);
                let resolved = await resolver.resolve4(altDomain);

                if (resolved && resolved.length) {
                    // wildcard DNS detected
                    let err = new Error(
                        `Wildcard DNS detected for ${name} of ${unicodeDomain(mainDomain)} [${unicodeDomain(altDomain)} resolved to ${resolved.join(', ')}]`
                    );
                    err.code = 'wildcard_dns';
                    throw err;
                }
            }
        } catch (err) {
            if (err.code === 'wildcard_dns') {
                throw err;
            }
            // otherwise ignore
        }
    }

    if (config?.checkUrl?.enabled) {
        try {
            let validated = await checkUrl(domain);
            if (!validated) {
                throw new Error('Domain validation failed');
            }
        } catch (err) {
            logger.error({ msg: 'Domain verification failed', domain, err });
            throw err;
        }
    }

    if (!config?.precheck?.length) {
        // pass by default if precheck rules not set
        return true;
    }

    for (let check of config.precheck) {
        const { key, expected } = check;

        let queryHandler;
        switch (key.toUpperCase()) {
            case 'A':
                queryHandler = 'resolve4';
                break;
            case 'AAAA':
                queryHandler = 'resolve6';
                break;
            case 'CNAME':
                queryHandler = 'resolveCname';
                break;
            default:
                queryHandler = `resolve${key.toLowerCase().replace(/^./, c => c.toUpperCase())}`;
        }

        if (typeof resolver[queryHandler] !== 'function') {
            let err = new Error(`Unknown RR type ${key} for ${name}`);
            err.code = 'unknown_rr_type';
            throw err;
        }

        let resolved;
        try {
            resolved = await resolver[queryHandler](domain);
        } catch (err) {
            logger.info({ msg: 'DNS query failed', action: 'precheck', queryHandler, domain, err });
        }

        if (!resolved || !resolved.length) {
            logger.info({ msg: 'DNS query failed', action: 'precheck', queryHandler, domain, err: 'Empty result' });
            continue;
        }

        logger.info({ msg: 'DNS query response', action: 'precheck', queryHandler, domain, resolved, expected });

        for (let row of resolved) {
            if ((row || '').toString().trim().toLowerCase() === expected.toLowerCase()) {
                return true;
            }
        }
    }

    let err = new Error(`Precheck failed for ${name}`);
    err.code = 'precheck_failed';
    throw err;
};

// Orders a certificate for `domain`, or returns false when no order can be
// attempted. The caller decides what to fall back to.
//
// `stored` is the record the caller has already read, if it has one. Both
// callers have: the read is what told them an order was needed at all, and
// reading it again here costs two more round trips and a decrypted private key
// per handshake.
const acquireCert = async (domain, stored) => {
    // Two reasons not to start, read together because this pair is what a flood
    // of names with no certificate hits on every single handshake. The first is
    // the account being over one of its limits, which is not something this
    // domain did and not something another order would get past; the second is
    // this domain's last attempt having failed recently.
    const [paused, blocked] = await areBlocked(pauseKey(), blockKey(domain));

    if (paused) {
        logger.info({ msg: 'Orders paused while the ACME account is rate limited', domain });
        return false;
    }

    if (blocked) {
        logger.info({ msg: 'Renewal blocked after a recent failure', domain });
        return false;
    }

    const store = getCerts();

    // A certificate written by an earlier release is imported here rather than on
    // the read path: a domain with nothing stored reaches this point anyway, and
    // one that still has life left in it is served without the validation below
    // ever running. Only a domain the store has never heard of is imported, so
    // that a record it has since ordered itself is not reverted to what an
    // earlier release left behind.
    let existing = stored === undefined ? await store.getCertificate(domain, true) : stored;
    if (!existing) {
        const imported = await importCertificate(store, domain);
        if (isUsable(imported) && !isRenewalDue(imported)) {
            return imported;
        }
        existing = imported;
    }

    // A domain holding a certificate that can still be served is renewing, and
    // has the rest of that certificate's life to manage it in. A domain with
    // nothing is being served the default certificate until this succeeds. They
    // are told apart because it decides which of the two gets the last of the
    // budget, and the answer is the renewal: see `renewalReserve` above.
    const renewal = isUsable(existing);

    // Budget for the DNS queries and the validation request, spent before either
    // is made rather than after.
    if (!(await spendValidation({ renewal })).granted) {
        logger.info({ msg: 'Out of validation budget', domain, renewal });
        await blockBriefly(blockKey(domain), BLOCK_NO_BUDGET_TTL);
        return false;
    }

    try {
        // throws if can not validate domain
        await validateDomain(domain);
        logger.info({ msg: 'Domain validation passed', domain });
    } catch (err) {
        logger.error({ msg: 'Failed to validate domain', domain, err });
        await blockRenewal(domain, err);
        return false;
    }

    // Budget for the order, which is the one the certificate authority counts.
    // Spent after the validation above rather than before it, on purpose: a
    // flood of names that were never pointed here would otherwise take the whole
    // order budget without a single one of them reaching the CA at all.
    if (!(await spendOrder({ renewal })).granted) {
        logger.info({ msg: 'Out of order budget', domain, renewal });
        await blockBriefly(blockKey(domain), BLOCK_NO_BUDGET_TTL);
        return false;
    }

    // The account of an instance upgraded in place is carried over before the
    // first order. A failed import is not fatal: the store registers a new
    // account instead, and the check costs one Redis read per order.
    await importAccount(store);

    // Read before the order, to tell a rate limit this call ran into apart from
    // one the store is only repeating back. See below.
    const attemptedAt = Date.now();

    let certificateData;
    try {
        certificateData = await store.acquireCert(domain);
    } catch (err) {
        await recordFailure(domain, err);
        throw err;
    }

    // `renewalError` describes this call and nothing else: the store sets it when
    // it was asked to renew and did not, and leaves it off every path where the
    // certificate is fine. `lastError` is the record's, written until an order
    // succeeds and handed straight back whenever the store attempted nothing at
    // all, so on its own it only means "something went wrong at some point",
    // which is not what this has to act on.
    const renewalError = certificateData && certificateData.renewalError;
    if (renewalError) {
        // This attempt did not renew. The store has a failsafe lock of its own
        // for that, but this is what keeps the validation above from running
        // again on the next handshake. The store swallows the error rather than
        // throwing it when there is still a certificate to serve, so this is the
        // only place a rate limit that arrived that way is seen.
        //
        // The pool wide pause is armed only for a rate limit this call was
        // actually answered with. A renewal the store refused because its own
        // failsafe lock is still holding reports the failure that armed the lock,
        // timestamp and all, and pausing every domain again for an hours old rate
        // limit each time that one record is read would escalate the pause until
        // the pool never came back.
        const answeredNow = new Date(renewalError.time).getTime() >= attemptedAt;
        await recordFailure(domain, renewalError, { pause: answeredNow });
        return certificateData;
    }

    if (isUsable(certificateData)) {
        await Promise.all([clearPauseBackoff(), clearRenewalBlock(domain)]);
    }

    return certificateData;
};

// Orders that are already running in this worker. The store locks per domain in
// Redis as well, but a burst of handshakes would otherwise leave every request
// waiting its turn on that lock for an order that is already under way.
const pendingRenewals = new Map();

const renew = (domain, stored) => coalesce(pendingRenewals, domain, () => acquireCert(domain, stored));

// The certificate to serve for `domain`, or false when there is nothing to serve
// and the SNI handler has to fall back to the default certificate.
const getCertificate = async domain => {
    domain = normalizeDomain(domain);

    if (!isValidDomain(domain)) {
        return false;
    }

    // Reads the store, never orders: everything that talks to the certificate
    // authority goes through renew(), which validates the domain first.
    const certificateData = await getCerts().getCertificate(domain, true);

    if (isUsable(certificateData)) {
        if (isRenewalDue(certificateData)) {
            // renewed in the background, while the certificate in place is served
            renew(domain, certificateData).catch(err => {
                logger.error({ msg: 'Cert renewal error', domain, err });
            });
        }

        return certificateData;
    }

    // nothing usable is stored, so the caller has to wait for the order. Only a
    // certificate that can actually be served is handed back, so that the SNI
    // handler can fall back to the default certificate for anything else.
    const renewed = await renew(domain, certificateData);
    return isUsable(renewed) ? renewed : false;
};

// Answers an http-01 challenge. Throws with a `responseCode` when the token is
// not one this instance is waiting for.
const resolveChallenge = (domain, token) => getCerts().routeHandler(domain, token);

// The domains the store holds a record for, and the record for one of them. The
// renewal pass in lib/renewal-sweeper.js reads the pool through these rather
// than reaching for the store, which stays behind this module the way the rest
// of the application already keeps it.
const listDomains = () => getCerts().listCertificateDomains();
const storedCertificate = domain => getCerts().getCertificate(domain, true);

module.exports = {
    getCertificate,
    resolveChallenge,

    // The renewal pass drives these; a handshake reaches them through
    // getCertificate() instead.
    renew,
    listDomains,
    storedCertificate,
    orderBudget,
    ordersPaused,
    poolKey,

    // Internals exposed for the test suite only, not part of the public API.
    testables: {
        blockKey,
        budgetKey,
        failureKey,
        getCerts,
        isUsable,
        pauseKey,
        pauseFailureKey,
        validateDomain,
        resolver,
        BLOCK_NO_BUDGET_TTL,
        BLOCK_RENEW_AFTER_FAILURE_TTL,
        BLOCK_RENEW_MAX_TTL,
        RATE_LIMITED
    }
};
