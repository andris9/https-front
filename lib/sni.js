'use strict';

const Joi = require('joi');
const { normalizeDomain } = require('./tools');
const { getCertificate } = require('./certs');
const { redisClient } = require('./db');
const config = require('wild-config');
const fs = require('fs');
const tls = require('tls');
const log = require('npmlog');

const ctxCache = new Map();
const sessionIdContext = config.https.sessionIdContext;

const defaultKey = fs.readFileSync(config.https.key, 'utf-8');
const defaultCert = fs.readFileSync(config.https.cert, 'utf-8');
const dhparam = fs.readFileSync(config.https.dhParam, 'utf-8');

const getSNIContext = async servername => {
    const domain = normalizeDomain(
        servername
            .split(':')
            .shift()
            .replace(/^www\./, '')
    );

    const validation = Joi.string()
        .domain({ tlds: { allow: true } })
        .validate(domain);

    if (validation.error) {
        // invalid domain name, can not create certificate
        return false;
    }

    const cert = await getCertificate(
        {
            redisClient,
            acme: config.acme
        },
        domain
    );

    if (!cert) {
        return false;
    }

    if (ctxCache.has(domain)) {
        let { expires, ctx } = ctxCache.get(domain);
        if (expires === cert.expires.getTime()) {
            return ctx;
        }
        ctxCache.delete(domain);
    }

    const ctxOpts = {
        key: cert.key,
        cert: [].concat(cert.cert).concat(cert.chain).join('\n\n')
    };

    const ctx = tls.createSecureContext(ctxOpts);

    ctxCache.set(domain, {
        expires: cert.expires.getTime(),
        ctx
    });

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
            .then(ctx => cb(null, ctx || defaultCtx))
            .catch(err => {
                log.error('HTTP', 'SNI failed for %s: %s', servername, err.message);
                return cb(null, defaultCtx);
            });
    }
};

module.exports = {
    getSNIContext,
    defaultCtx,
    httpsCredentials
};
