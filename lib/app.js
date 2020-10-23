'use strict';

const { proxyServer } = require('./proxy-server');
const config = require('wild-config');
const { normalizeIp, getHostname } = require('./tools');
const RedisChallenge = require('./redis-challenge');
const { redisClient } = require('./db');
const log = require('npmlog');

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

module.exports = { app };
