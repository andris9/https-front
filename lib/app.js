'use strict';

const { proxyServer } = require('./proxy-server');
const config = require('wild-config');
const { normalizeIp, getHostname } = require('./tools');
const RedisChallenge = require('./redis-challenge');
const { redisClient } = require('./db');

const pino = require('pino')();
const logger = pino.child({ app: 'https-front', component: 'app' });

const ACME_PREFIX = '/.well-known/acme-challenge/';

const redisChallenge = RedisChallenge.create({
    hashKey: `acme:challenge:${config.acme.key}`,
    redisClient
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
                    let err = new Error(`Unknown challenge`);
                    err.statusCode = 404;
                    throw err;
                }
                res.statusCode = 200;
                res.setHeader('Content-Type', 'text/plain');
                res.end(val.keyAuthorization);
                logger.debug({
                    msg: 'Resolved authorization token',
                    domain: req.domain,
                    remoteAddress: req.ip,
                    url: req.url,
                    token,
                    keyAuthorization: val.keyAuthorization
                });
            })
            .catch(err => {
                res.statusCode = err.statusCode || 500;
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
