'use strict';

const { coalesce, normalizeDomain, isValidDomain } = require('./tools');
const { getCertificate } = require('./certs');
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

// Domains with no certificate are remembered in a cache of their own rather than
// among the contexts. Sharing one would make a run of names that have nothing
// stored evict a live context each, so a scan working through a list of domains
// would empty every worker's cache behind it and leave each real handshake
// afterwards reading Redis and parsing a certificate again. Keeping them apart
// bounds what a flood of unknown names can cost the domains actually being
// served.
const missCache = new Map();

// contextCacheTtl and contextCacheSize are configurable because they are what an
// operator has to read against the size of the pool being fronted. The rest are
// internals.
const contextTtl = () => (config.https.contextCacheTtl || 60) * 1000;

const limits = {
    // how long a domain with no certificate is remembered
    missingTtl: 30 * 1000,
    // Upper bound on the number of cached contexts. A context holds a parsed
    // certificate and private key, so raising this is paid for in memory.
    cacheSize: Number(config.https.contextCacheSize) > 0 ? Number(config.https.contextCacheSize) : 5000,
    // And on the misses. A miss is one timestamp, so this can be far larger than
    // the contexts it is protecting without costing anything like as much.
    missCacheSize: 50000
};

const cacheGet = (cache, domain) => {
    const entry = cache.get(domain);
    if (!entry) {
        return false;
    }
    // move the entry to the end, where the most recently used ones live
    cache.delete(domain);
    cache.set(domain, entry);
    return entry;
};

const cacheSet = (cache, size, domain, entry) => {
    // cacheGet has already moved an existing key to the end, so set() overwrites
    // it in place at the most recently used position
    cache.set(domain, entry);

    while (cache.size > size) {
        // the first key is the least recently used one
        cache.delete(cache.keys().next().value);
    }
};

// Handshakes that arrive while a lookup is already running wait for it instead
// of starting one of their own.
const pendingLookups = new Map();

const lookupCertificate = domain => coalesce(pendingLookups, domain, () => getCertificate(domain));

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

    const missed = cacheGet(missCache, domain);
    if (missed && missed.checkAfter > Date.now()) {
        return false;
    }

    const cached = cacheGet(ctxCache, domain);
    if (cached && cached.checkAfter > Date.now()) {
        return cached.ctx;
    }

    const cert = await lookupCertificate(domain);
    const now = Date.now();

    if (!cert) {
        // Remember the miss for a while. Without it every handshake for a domain
        // with no certificate repeats the lookup.
        cacheSet(missCache, limits.missCacheSize, domain, { checkAfter: now + limits.missingTtl });
        return false;
    }

    // an order that has since gone through settles what the miss recorded
    missCache.delete(domain);

    const expires = new Date(cert.validTo).getTime();
    // A renewal replaces both of these, so either one changing means the context
    // has to be built again. The fingerprint is the real identity; the expiry
    // still answers for a record that was stored without one.
    const fingerprint = cert.fingerprint || null;

    // Read again rather than trusting the entry from before the lookup: a
    // handshake that arrived in the same burst may already have built this
    // context, and the entry may have been evicted in the meantime.
    const current = cacheGet(ctxCache, domain);
    const ctx =
        current && current.ctx && current.fingerprint === fingerprint && current.expires === expires
            ? // the same certificate as before, so is the context built from it
              current.ctx
            : tls.createSecureContext({
                  key: cert.privateKey,
                  cert: []
                      .concat(cert.cert)
                      .concat(cert.ca || [])
                      .join('\n\n')
              });

    // the check interval never reaches past the expiry of the certificate itself
    cacheSet(ctxCache, limits.cacheSize, domain, { ctx, expires, fingerprint, checkAfter: Math.min(now + contextTtl(), expires) });
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
        missCache,
        limits
    }
};
