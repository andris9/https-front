'use strict';

const Joi = require('joi');
const { normalizeDomain } = require('./tools');
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

// Read at call time, so a configuration reload takes effect without a restart.
const contextTtl = () => (config.https.contextCacheTtl || 60) * 1000;
const missingContextTtl = () => (config.https.missingContextTtl || 30) * 1000;
const contextCacheSize = () => config.https.contextCacheSize || 5000;

// An entry can be served while its check interval is still running. A context
// whose certificate expired in the meantime never can; a remembered miss has no
// certificate to expire.
const isFresh = (entry, now) => entry.checkAfter > now && (!entry.ctx || entry.expires > now);

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
    ctxCache.delete(domain);
    ctxCache.set(domain, entry);

    while (ctxCache.size > contextCacheSize()) {
        // the first key is the least recently used one
        ctxCache.delete(ctxCache.keys().next().value);
    }

    return entry.ctx;
};

const sessionIdContext = config.https.sessionIdContext;

const defaultKey = fs.readFileSync(config.https.key, 'utf-8');
const defaultCert = fs.readFileSync(config.https.cert, 'utf-8');
const dhparam = fs.readFileSync(config.https.dhParam, 'utf-8');

const getSNIContext = async servername => {
    const domain = normalizeDomain(servername.split(':').shift());

    const validation = Joi.string()
        .domain({ tlds: { allow: true } })
        .validate(domain);

    if (validation.error) {
        // invalid domain name, can not create certificate
        return false;
    }

    const cached = cacheGet(domain);
    if (cached && isFresh(cached, Date.now())) {
        return cached.ctx;
    }

    const cert = await getCertificate(
        {
            redisClient,
            acme: config.acme
        },
        domain
    );

    if (!cert) {
        // Remember the miss for a while. Without it every handshake for a domain
        // that has no certificate repeats the Redis lookup and, for a domain that
        // fails validation, the DNS queries behind it.
        return cacheSet(domain, { ctx: false, checkAfter: Date.now() + missingContextTtl() });
    }

    const expires = new Date(cert.expires).getTime();

    if (cached && cached.ctx && cached.expires === expires) {
        // the same certificate as before, keep the context and start the check
        // interval over
        cached.checkAfter = Date.now() + contextTtl();
        return cached.ctx;
    }

    const ctx = tls.createSecureContext({
        key: cert.key,
        cert: [].concat(cert.cert).concat(cert.chain).join('\n\n')
    });

    return cacheSet(domain, { ctx, expires, checkAfter: Date.now() + contextTtl() });
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
        ctxCache
    }
};
