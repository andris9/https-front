'use strict';

/* eslint global-require: 0 */

const cluster = require('cluster');
const log = require('npmlog');
const config = require('wild-config');

let closing = false;
const closeProcess = code => {
    if (closing) {
        return;
    }
    closing = true;
    setTimeout(() => {
        process.exit(code);
    }, 10);
};

process.on('uncaughtException', () => closeProcess(1));
process.on('unhandledRejection', () => closeProcess(2));
process.on('SIGTERM', () => closeProcess(0));
process.on('SIGINT', () => closeProcess(0));

if (cluster.isMaster) {
    process.title = 'https-front: main';
    log.info('Cluster', 'Master process started');

    const fork = () => {
        if (closing) {
            return;
        }
        let worker = cluster.fork();
        worker.on('online', () => {
            log.info('Cluster', 'Worker came online: %s', worker.process.pid);
        });
    };

    for (let i = 0; i < config.proxy.workers; i++) {
        fork();
    }

    cluster.on('exit', (worker, code, signal) => {
        if (closing) {
            return;
        }
        log.info('Cluster', 'Worker died: %s (%s, %s)', worker.process.pid, code, signal);
        setTimeout(() => fork(), 2000).unref();
    });
} else {
    process.title = 'https-front: worker';
    // worker to serve public websites
    require('./worker.js');
}
