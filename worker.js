'use strict';

const http = require('http');
const https = require('https');

const config = require('@zone-eu/wild-config');
const { httpsCredentials } = require('./lib/sni');
const { redisClient } = require('./lib/db');
const { app } = require('./lib/app');

const { componentLogger } = require('./lib/logger');
const logger = componentLogger('worker');

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
        .set(`tls:${id.toString('hex')}`, data, 'EX', 30 * 60)
        .then(() => {
            cb();
        })
        .catch(err => {
            logger.error({ msg: 'Failed to store TLS ticket', id, data, err });
            cb();
        });
});

httpsServer.on('resumeSession', (id, cb) => {
    redisClient
        // read the ticket and extend it in one round trip
        .getexBuffer(`tls:${id.toString('hex')}`, 'EX', 300)
        .then(session => {
            cb(null, session || null);
        })
        .catch(err => {
            logger.error({ msg: 'Failed to retrieve TLS ticket', err, id });
            cb(null);
        });
});

httpsServer.on('error', err => {
    logger.error({ msg: 'Web server error', proto: 'https', err });
});

httpServer.on('error', err => {
    logger.error({ msg: 'Web server error', proto: 'http', err });
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
                logger.info({ msg: 'Changed group', group: config.proxy.group, gid: process.getgid() });
            } catch (E) {
                logger.fatal({ msg: 'Failed to change group', group: config.proxy.group, err: E });
                return setTimeout(() => process.exit(1), 3000);
            }
        }
        if (config.proxy.user) {
            try {
                process.setuid(config.proxy.user);
                logger.info({ msg: 'Changed user', user: config.proxy.user, uid: process.getuid() });
            } catch (E) {
                logger.fatal({ msg: 'Failed to change user', user: config.proxy.user, err: E });
                return setTimeout(() => process.exit(1), 3000);
            }
        }

        logger.info('Server started');
    })
    .catch(err => {
        logger.fatal({ msg: 'Failed to start server', err });
        process.exit(1);
    });
