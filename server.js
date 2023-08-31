'use strict';

/* eslint global-require: 0 */

const cluster = require('cluster');
const config = require('wild-config');
const pino = require('pino')();
const logger = pino.child({ app: 'https-front', component: 'cluster' });

let closing = false;
const closeProcess = code => {
    if (closing) {
        return;
    }
    closing = true;
    if (cluster.isMaster) {
        logger.info({ msg: 'Closing the application...', code });
    }
    process.exit(code);
};

process.on('uncaughtException', err => {
    logger.fatal({ msg: 'uncaughtException', err });
    closeProcess(1);
});

process.on('unhandledRejection', err => {
    logger.fatal({ msg: 'uncaughtException', err });
    closeProcess(2);
});

process.on('SIGTERM', () => {
    if (cluster.isMaster) {
        logger.info({ msg: 'Received SIGTERM', signal: 'SIGTERM' });
    }
    closeProcess(0);
});

process.on('SIGINT', () => {
    if (cluster.isMaster) {
        logger.info({ msg: 'Received SIGINT', signal: 'SIGINT' });
    }
    closeProcess(0);
});

if (cluster.isMaster) {
    process.title = 'https-front: main';
    logger.info({ msg: 'Master process started', workers: config.proxy.workers });

    const fork = () => {
        if (closing) {
            return;
        }
        let worker = cluster.fork();
        worker.on('online', () => {
            logger.info({ msg: 'Worker came online', worker: worker.process.pid });
        });
    };

    for (let i = 0; i < config.proxy.workers; i++) {
        fork();
    }

    cluster.on('exit', (worker, code, signal) => {
        if (closing) {
            return;
        }
        logger.error({ msg: 'Worker died', worker: worker.process.pid, code, signal });
        setTimeout(() => fork(), 2000).unref();
    });
} else {
    process.title = 'https-front: worker';
    // worker to serve public websites
    require('./worker.js');
}
