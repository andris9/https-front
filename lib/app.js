'use strict';

const { proxyServer } = require('./proxy-server');
const config = require('@zone-eu/wild-config');
const { normalizeIp, getHostname } = require('./tools');
const { resolveChallenge } = require('./certs');

const { componentLogger } = require('./logger');
const logger = componentLogger('app');

const ACME_PREFIX = '/.well-known/acme-challenge/';

const app = (req, res) => {
    req.ip = normalizeIp(res.socket.remoteAddress);
    req.domain = getHostname(req);
    // start of the request, used for the access log in proxy-server.js
    req.stats = { time: Date.now() };

    if (req.url.indexOf(ACME_PREFIX) === 0) {
        const token = req.url.slice(ACME_PREFIX.length);

        return resolveChallenge(req.domain, token)
            .then(keyAuthorization => {
                res.statusCode = 200;
                // RFC 8555 section 8.3: the key authorization is the whole body,
                // compared byte for byte, so it is handed back as an opaque one
                res.setHeader('Content-Type', 'application/octet-stream');
                res.end(keyAuthorization);
                logger.debug({
                    msg: 'Resolved authorization token',
                    domain: req.domain,
                    remoteAddress: req.ip,
                    url: req.url,
                    token,
                    keyAuthorization
                });
            })
            .catch(err => {
                res.statusCode = err.responseCode || 500;
                res.setHeader('Content-Type', 'text/plain');
                res.end('Failed to verify authorization token');
                logger.error({
                    msg: 'Failed to verify authorization token',
                    domain: req.domain,
                    remoteAddress: req.ip,
                    url: req.url,
                    token,
                    status: res.statusCode,
                    userAgent: req.headers['user-agent'] || '',
                    err
                });
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

module.exports = { app };
