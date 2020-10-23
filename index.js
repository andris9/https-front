'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const tls = require('tls');

const config = require('wild-config');
const RedisChallenge = require('./lib/redis-challenge');
const Joi = require('joi');
const httpProxy = require('http-proxy');
const log = require('npmlog');
const { normalizeDomain, normalizeIp } = require('./lib/tools');

const { redisClient } = require('./lib/db');

const redisChallenge = RedisChallenge.create({
    hashKey: `acme:challenge:${config.acme.key}`,
    redisClient
});

const ACME_PREFIX = '/.well-known/acme-challenge/';

const ctxCache = new Map();

const defaultKey = fs.readFileSync(config.https.key, 'utf-8');
const defaultCert = fs.readFileSync(config.https.cert, 'utf-8');
const dhparam = fs.readFileSync(config.https.dhParam, 'utf-8');
const sessionIdContext = 'projectpending';

let defaultCtx = tls.createSecureContext({
    key: defaultKey,
    cert: defaultCert,
    dhparam,
    sessionIdContext
});

const { getCertificate } = require('./lib/certs');

const credentials = { key: defaultKey, cert: defaultCert, dhparam, sessionIdContext };

const getHostname = req => {
    let host =
        []
            .concat(req.headers.host || [])
            .concat(req.authority || [])
            .concat(req.ip || [])
            .shift() || '';
    host = host.split(':').shift();

    if (host) {
        host = normalizeDomain(host);
    }

    return host;
};

const proxyServer = httpProxy.createProxyServer({});

proxyServer.on('proxyReq', (proxyReq, req) => {
    proxyReq.setHeader('X-Forwarded-Proto', req.proto);
    proxyReq.setHeader('X-Connecting-IP', req.ip);
    req.stats = {
        time: Date.now()
    };
});

proxyServer.on('proxyRes', (proxyReq, req) => {
    log.http('Proxy', `c=%s p=%s d=%s u=%s t=%sms s=%s`, req.ip, req.proto, req.domain, req.url, Date.now() - req.stats.time, proxyReq.statusCode);
});

proxyServer.on('error', (err, req, res) => {
    res.writeHead(500, {
        'Content-Type': 'text/plain'
    });
    res.end('Something went wrong. And we are reporting a custom error message.');
    log.http('Proxy', `c=%s p=%s d=%s u=%s t=%sms s=%s e=%s`, req.ip, req.proto, req.domain, req.url, Date.now() - req.stats.time, 502, err.message);
});

const app = (req, res) => {
    req.ip = normalizeIp(res.socket.remoteAddress);
    req.domain = getHostname(req);

    if (req.url.indexOf(ACME_PREFIX) === 0) {
        const token = req.url.slice(ACME_PREFIX.length);

        return redisChallenge
            .get({
                challenge: {
                    token,
                    identifier: { value: req.domain }
                }
            })
            .then(val => {
                if (!val || !val.keyAuthorization) {
                    throw new Error('Unknown challenge');
                }
                res.statusCode = 200;
                res.setHeader('Content-Type', 'text/plain');
                res.end(val.keyAuthorization);
            })
            .catch(err => {
                res.statusCode = 500;
                res.setHeader('Content-Type', 'text/plain');
                res.end('Failed to verify authentication token');
                log.error('HTTP', err);
            });
    }

    let rUrl = new URL(config.proxy.origin);
    return proxyServer.web(req, res, {
        target: rUrl.origin,
        changeOrigin: false,
        xfwd: true,
        secure: false,
        prependPath: true,
        autoRewrite: true
    });
};

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

credentials.SNICallback = (servername, cb) => {
    getSNIContext(servername)
        .then(ctx => {
            return cb(null, ctx || defaultCtx);
        })
        .catch(err => {
            log.error('HTTP', 'SNI failed for %s: %s', servername, err.stack);
            return cb(null, defaultCtx);
        });
};

const httpServer = http.createServer((req, res) => {
    req.proto = 'http';
    return app(req, res);
});

const httpsServer = https.createServer(credentials, (req, res) => {
    req.proto = 'https';
    return app(req, res);
});

httpsServer.on('newSession', function (id, data, cb) {
    redisClient
        .multi()
        .set(`tls:${id.toString('hex')}`, data)
        .expire(`tls:${id.toString('hex')}`, 30 * 60)
        .exec()
        .then(() => {
            cb();
        })
        .catch(err => {
            log.error('TLS', 'Failed to store TLS ticket: %s', err.stack);
            cb();
        });
});

httpsServer.on('resumeSession', function (id, cb) {
    redisClient
        .multi()
        .getBuffer(`tls:${id.toString('hex')}`)
        // extend ticket
        .expire(`tls:${id.toString('hex')}`, 300)
        .exec()
        .then(result => {
            cb(null, result?.[0]?.[1] || null);
        })
        .catch(err => {
            log.error('TLS', 'Failed to retrieve TLS ticket: %s', err.stack);
            cb(null);
        });
});

httpsServer.on('error', err => {
    log.error('HTTPS', 'HTTPS server error: %s', err.stack);
});

httpServer.on('error', err => {
    log.error('HTTP', 'HTTP server error: %s', err.stack);
});

const startHttp = () => {
    return new Promise((resolve, reject) => {
        httpServer.once('error', reject);
        httpServer.listen(config.http.port, () => resolve());
    });
};

const startHttps = () => {
    return new Promise((resolve, reject) => {
        httpsServer.once('error', reject);
        httpsServer.listen(config.https.port, () => resolve());
    });
};

const start = async () => {
    await Promise.all([startHttp(), startHttps()]);
};

start()
    .then(() => {
        log.info('Server', 'Server started');
    })
    .catch(err => {
        log.error('Server', err);
        process.exit(1);
    });
