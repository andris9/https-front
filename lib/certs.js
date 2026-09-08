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
const { coalesce, normalizeDomain, isValidDomain } = require('./tools');
const { checkUrl } = require('./check-url');
const { importAccount, importCertificate } = require('./legacy-certs');

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
const BLOCK_RENEW_AFTER_FAILURE_TTL = 300;
const CAA_DOMAIN = 'letsencrypt.org';

// Everything this instance stores lives under this prefix, which keeps a staging
// pool and a production pool apart in one Redis database the way the
// `acme:certificate:<key>:*` keys of earlier releases did.
const NAMESPACE = `acme:${config.acme.key}`;

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

// Marks a domain whose last attempt failed. Keyed the way every other name in
// this module is, which is not how the store spells its own keys, so this stays
// this module's own bookkeeping rather than a guess at the store's.
const blockKey = domain => `${NAMESPACE}:blocked:${domain}`;

const blockRenewal = async domain => {
    // Recorded in Redis rather than in the worker, so that every worker and
    // every instance sharing this certificate pool backs off too.
    try {
        await redisClient.set(blockKey(domain), 1, 'EX', BLOCK_RENEW_AFTER_FAILURE_TTL);
    } catch (err) {
        logger.info({ msg: 'Redis call failed', key: blockKey(domain), domain, err });
    }
};

// True while the stored certificate can still be served. A renewal that can not
// be attempted leaves the current certificate in place, but an expired one is
// never handed back, and neither is the key-only record an order in flight
// leaves behind. An unreadable expiry compares false, which is the answer that
// keeps the SNI handler on the default certificate.
const isUsable = certificateData =>
    Boolean(certificateData && certificateData.cert && certificateData.privateKey && new Date(certificateData.validTo).getTime() > Date.now());

const validateDomain = async domain => {
    // check domain name format
    if (!isValidDomain(domain)) {
        // invalid domain name, can not create certificate
        let err = new Error(`${domain} is not a valid domain name`);
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
            let err = new Error(`LE not listed in the CAA record for ${subdomain} (${domain})`);
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
                    let err = new Error(`Wildcard DNS detected for ${domain} of ${mainDomain} [${altDomain} resolved to ${resolved.join(', ')}]`);
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
            let err = new Error(`Unknown RR type ${key} for ${domain}`);
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

    let err = new Error(`Precheck failed for ${domain}`);
    err.code = 'precheck_failed';
    throw err;
};

// Orders a certificate for `domain`, or returns false when no order can be
// attempted. The caller decides what to fall back to.
const acquireCert = async domain => {
    // The last attempt failed recently, so nothing here would go any better.
    if (await redisClient.exists(blockKey(domain))) {
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
    if (!(await store.getCertificate(domain, true))) {
        const imported = await importCertificate(store, domain);
        if (isUsable(imported) && !isRenewalDue(imported)) {
            return imported;
        }
    }

    try {
        // throws if can not validate domain
        await validateDomain(domain);
        logger.info({ msg: 'Domain validation passed', domain });
    } catch (err) {
        logger.error({ msg: 'Failed to validate domain', domain, err });
        await blockRenewal(domain);
        return false;
    }

    // The account of an instance upgraded in place is carried over before the
    // first order. A failed import is not fatal: the store registers a new
    // account instead, and the check costs one Redis read per order.
    await importAccount(store);

    let certificateData;
    try {
        certificateData = await store.acquireCert(domain);
    } catch (err) {
        await blockRenewal(domain);
        throw err;
    }

    if (certificateData && certificateData.lastError) {
        // The order did not go through. The store has a failsafe lock of its own
        // for that, but this is what keeps the validation above from running
        // again on the next handshake.
        await blockRenewal(domain);
    }

    return certificateData;
};

// Orders that are already running in this worker. The store locks per domain in
// Redis as well, but a burst of handshakes would otherwise leave every request
// waiting its turn on that lock for an order that is already under way.
const pendingRenewals = new Map();

const renew = domain => coalesce(pendingRenewals, domain, () => acquireCert(domain));

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
            renew(domain).catch(err => {
                logger.error({ msg: 'Cert renewal error', domain, err });
            });
        }

        return certificateData;
    }

    // nothing usable is stored, so the caller has to wait for the order. Only a
    // certificate that can actually be served is handed back, so that the SNI
    // handler can fall back to the default certificate for anything else.
    const renewed = await renew(domain);
    return isUsable(renewed) ? renewed : false;
};

// Answers an http-01 challenge. Throws with a `responseCode` when the token is
// not one this instance is waiting for.
const resolveChallenge = (domain, token) => getCerts().routeHandler(domain, token);

module.exports = {
    getCertificate,
    resolveChallenge,

    // Internals exposed for the test suite only, not part of the public API.
    testables: {
        blockKey,
        getCerts,
        isUsable,
        validateDomain,
        resolver
    }
};
