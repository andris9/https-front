'use strict';

const http = require('http');
const https = require('https');

const config = require('wild-config');
const log = require('npmlog');
const { httpsCredentials } = require('./lib/sni');
const { redisClient } = require('./lib/db');
const { app } = require('./lib/app');

const httpServer = http.createServer((req, res) => {
    req.proto = 'http';
    return app(req, res);
});

const httpsServer = https.createServer(httpsCredentials, (req, res) => {
    req.proto = 'https';
    return app(req, res);
});

httpsServer.on('newSession', (id, data, cb) => {
    redisClient
        .multi()
        .set(`tls:${id.toString('hex')}`, data)
        .expire(`tls:${id.toString('hex')}`, 30 * 60)
        .exec()
        .then(() => {
            cb();
        })
        .catch(err => {
            log.error('TLS', 'Failed to store TLS ticket: %s', err.message);
            cb();
        });
});

httpsServer.on('resumeSession', (id, cb) => {
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
            log.error('TLS', 'Failed to retrieve TLS ticket: %s', err.message);
            cb(null);
        });
});

httpsServer.on('error', err => {
    log.error('HTTPS', 'HTTPS server error: %s', err.message);
});

httpServer.on('error', err => {
    log.error('HTTP', 'HTTP server error: %s', err.message);
});

const startHttp = () =>
    new Promise((resolve, reject) => {
        httpServer.once('error', reject);
        httpServer.listen(config.http.port, config.http.host, () => resolve());
    });

const startHttps = () =>
    new Promise((resolve, reject) => {
        httpsServer.once('error', reject);
        httpsServer.listen(config.https.port, config.https.host, () => resolve());
    });

const start = async () => {
    await Promise.all([startHttp(), startHttps()]);
};

start()
    .then(() => {
        if (config.proxy.group) {
            try {
                process.setgid(config.proxy.group);
                log.info('Worker', 'Changed group to "%s" (%s)', config.proxy.group, process.getgid());
            } catch (E) {
                log.error('Worker', 'Failed to change group to "%s" (%s)', config.proxy.group, E.message);
                return setTimeout(() => process.exit(1), 3000);
            }
        }
        if (config.proxy.user) {
            try {
                process.setuid(config.proxy.user);
                log.info('Worker', 'Changed user to "%s" (%s)', config.proxy.user, process.getuid());
            } catch (E) {
                log.error('Worker', 'Failed to change user to "%s" (%s)', config.proxy.user, E.message);
                return setTimeout(() => process.exit(1), 3000);
            }
        }

        log.info('Worker', 'Server started');
    })
    .catch(err => {
        log.error('Worker', err);
        process.exit(1);
    });
