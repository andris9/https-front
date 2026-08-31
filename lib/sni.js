'use strict';

const { normalizeDomain, isValidDomain } = require('./tools');
const { getCertificate } = require('./certs');
const { redisClient } = require('./db');
const config = require('@zone-eu/wild-config');
const fs = require('fs');
const tls = require('tls');

const { componentLogger } = require('./logger');
const logger = componentLogger('sni');

// TLS contexts are cached per domain. The cache exists to keep a handshake from
// reading the certificate out of Redis and parsing it every time, so an entry is
// served as is until its check interval has passed; revalidating against Redis
// after that is what picks up a renewal. Insertion order doubles as the LRU
// order, and the cache is capped, because this proxy is meant to front an
// unknown number of domains and nothing else would ever evict an entry for a
// domain that stopped being requested.
const ctxCache = new Map();

// contextCacheTtl is configurable because it bounds how long a renewal takes to
// reach a worker, which an operator may want to tune. The rest are internals.
const contextTtl = () => (config.https.contextCacheTtl || 60) * 1000;

const limits = {
    // how long a domain with no certificate is remembered
    missingTtl: 30 * 1000,
    // upper bound on the number of cached contexts
    cacheSize: 5000
};

const cacheGet = domain => {
    const entry = ctxCache.get(domain);
    if (!entry) {
        return false;
    }
    // move the entry to the end, where the most recently used ones live
    ctxCache.delete(domain);
    ctxCache.set(domain, entry);
    return entry;
};

const cacheSet = (domain, entry) => {
    // cacheGet has already moved an existing key to the end, so set() overwrites
    // it in place at the most recently used position
    ctxCache.set(domain, entry);

    while (ctxCache.size > limits.cacheSize) {
        // the first key is the least recently used one
        ctxCache.delete(ctxCache.keys().next().value);
    }
};

// Handshakes that arrive while a lookup is already running wait for it instead
// of starting one of their own, the same way ensureAcme shares its init promise.
const pendingLookups = new Map();

const lookupCertificate = domain => {
    let pending = pendingLookups.get(domain);
    if (!pending) {
        pending = getCertificate({ redisClient, acme: config.acme }, domain).finally(() => pendingLookups.delete(domain));
        pendingLookups.set(domain, pending);
    }
    return pending;
};

const sessionIdContext = config.https.sessionIdContext;

const defaultKey = fs.readFileSync(config.https.key, 'utf-8');
const defaultCert = fs.readFileSync(config.https.cert, 'utf-8');
const dhparam = fs.readFileSync(config.https.dhParam, 'utf-8');

const getSNIContext = async servername => {
    const domain = normalizeDomain(servername.split(':').shift());

    if (!isValidDomain(domain)) {
        // invalid domain name, can not create certificate
        return false;
    }

    const cached = cacheGet(domain);
    if (cached && cached.checkAfter > Date.now()) {
        return cached.ctx;
    }

    const cert = await lookupCertificate(domain);
    const now = Date.now();

    if (!cert) {
        // Remember the miss for a while. Without it every handshake for a domain
        // with no certificate repeats the lookup.
        cacheSet(domain, { ctx: false, checkAfter: now + limits.missingTtl });
        return false;
    }

    const expires = new Date(cert.expires).getTime();

    // Read again rather than trusting the entry from before the lookup: a
    // handshake that arrived in the same burst may already have built this
    // context, and the entry may have been evicted in the meantime.
    const current = cacheGet(domain);
    const ctx =
        current && current.ctx && current.expires === expires
            ? // the same certificate as before, so is the context built from it
              current.ctx
            : tls.createSecureContext({
                  key: cert.key,
                  cert: [].concat(cert.cert).concat(cert.chain).join('\n\n')
              });

    // the check interval never reaches past the expiry of the certificate itself
    cacheSet(domain, { ctx, expires, checkAfter: Math.min(now + contextTtl(), expires) });
    return ctx;
};

const defaultCtx = tls.createSecureContext({
    key: defaultKey,
    cert: defaultCert,
    dhparam,
    sessionIdContext
});

const httpsCredentials = {
    key: defaultKey,
    cert: defaultCert,
    dhparam,
    sessionIdContext,
    SNICallback(servername, cb) {
        getSNIContext(servername)
            .then(ctx => {
                logger.info({ msg: 'SNI handler', servername, match: !!ctx });
                cb(null, ctx || defaultCtx);
            })
            .catch(err => {
                logger.error({ msg: 'SNI failed', servername, err });
                return cb(null, defaultCtx);
            });
    }
};

module.exports = {
    getSNIContext,
    defaultCtx,
    httpsCredentials,

    // Internals exposed for the test suite only, not part of the public API.
    testables: {
        ctxCache,
        limits
    }
};
