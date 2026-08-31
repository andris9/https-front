'use strict';

// Shared helpers for the test suite. Tests must run with NODE_ENV=test so that
// config/test.toml points Redis at the dedicated test database (db 15), the
// servers at loopback ports and the logger at "silent".

const http = require('node:http');
const tls = require('node:tls');

if (!process.env.NODE_ENV) {
    process.env.NODE_ENV = 'test';
}

const config = require('@zone-eu/wild-config');
const { redisClient } = require('../lib/db');
const { certificateKey } = require('../lib/certs').testables;

const DAY = 24 * 3600 * 1000;

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// Poll `check` until it returns something truthy, or give up. Returns the last
// value, so a caller can assert on it either way.
const waitFor = async (check, { timeout = 20000, interval = 25 } = {}) => {
    const deadline = Date.now() + timeout;
    for (;;) {
        const value = await check();
        if (value || Date.now() >= deadline) {
            return value;
        }
        await delay(interval);
    }
};

// Flush the dedicated test database. Refuses to run unless Redis is pointed at
// db 15, to avoid wiping development (db 4) or production data by accident.
const flushTestDb = async () => {
    if (Number(config.redis && config.redis.db) !== 15) {
        throw new Error(
            `Refusing to flush Redis: expected the test database (db 15) but config points at db ${config.redis && config.redis.db}. Run tests with NODE_ENV=test.`
        );
    }
    try {
        await redisClient.flushdb();
    } catch (err) {
        throw new Error(`The test suite needs a Redis server on ${config.redis.host}:${config.redis.port} (${err.message})`, { cause: err });
    }
};

// Close the Redis connection so the test process can exit cleanly.
const closeDb = async () => {
    await redisClient.quit().catch(() => false);
};

// Start an HTTP server on a random loopback port. Returns the server, its port
// and its base URL, plus a close() that resolves once the port is free again.
const startServer = handler =>
    new Promise((resolve, reject) => {
        const server = http.createServer(handler);
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const { port } = server.address();
            resolve({
                server,
                port,
                url: `http://127.0.0.1:${port}`,
                close: () =>
                    new Promise(done => {
                        server.closeAllConnections();
                        server.close(() => done());
                    })
            });
        });
    });

// A server that records every request it receives and replies with whatever the
// current test asked for.
const startRecordingServer = async (initialReply = {}) => {
    const received = [];
    let reply = Object.assign({ status: 200, body: '', contentType: 'text/plain' }, initialReply);

    const handle = await startServer((req, res) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => {
            received.push({
                method: req.method,
                url: req.url,
                headers: req.headers,
                body: Buffer.concat(chunks).toString()
            });
            res.writeHead(reply.status, { 'Content-Type': reply.contentType });
            res.end(reply.body);
        });
    });

    return Object.assign(handle, {
        received,
        respondWith(next) {
            reply = Object.assign({ status: 200, contentType: 'application/json' }, next);
        }
    });
};

// A stub ACME directory, enough for acme.init() to succeed without reaching out
// to Let's Encrypt. Points config.acme.directoryUrl at itself and restores it on
// close. requestCount() reports how often the directory was fetched.
const startAcmeDirectory = async () => {
    const originalDirectoryUrl = config.acme.directoryUrl;
    const state = { requests: 0 };

    const handle = await startServer((req, res) => {
        state.requests++;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
            JSON.stringify({
                keyChange: `${handle.url}/acme/key-change`,
                meta: { termsOfService: `${handle.url}/terms` },
                newAccount: `${handle.url}/acme/new-acct`,
                newNonce: `${handle.url}/acme/new-nonce`,
                newOrder: `${handle.url}/acme/new-order`,
                revokeCert: `${handle.url}/acme/revoke-cert`
            })
        );
    });

    config.acme.directoryUrl = `${handle.url}/directory`;

    const close = handle.close;
    return Object.assign(handle, {
        requestCount: () => state.requests,
        close: async () => {
            config.acme.directoryUrl = originalDirectoryUrl;
            await close();
        }
    });
};

// The options object every lib/certs.js entry point takes.
const acmeOptions = () => ({ redisClient, acme: config.acme });

// The Redis key lib/certs.js stores a certificate under.
const certKeyFor = domain => certificateKey(config.acme.key, [domain]);

// Store a certificate for `domain` that expires at `expires` after a lifetime of
// `lifetime`, which is what the renewal maths measures against.
const seedCertificate = async (domain, { expires, lifetime = 90 * DAY, key = 'stored-private-key', cert = 'stored-cert' } = {}) => {
    const certKey = certKeyFor(domain);
    await redisClient.hmset(certKey, {
        key,
        cert,
        chain: 'stored-chain',
        validFrom: new Date(expires - lifetime).toISOString(),
        expires: new Date(expires).toISOString(),
        dnsNames: JSON.stringify([domain]),
        issuer: 'Test CA',
        status: 'valid'
    });
    return certKey;
};

// Keep domain validation local: no DNS lookups, no validation endpoint. Returns
// a restore() that puts the original configuration back.
const useLocalDomainChecks = () => {
    const original = {
        extraChecks: config.extraChecks,
        precheck: config.precheck,
        checkUrl: config.checkUrl
    };

    config.extraChecks = { wildCardAllowed: true };
    config.precheck = [];
    config.checkUrl = { enabled: false };

    return () => Object.assign(config, original);
};

// Minimal HTTP client. node:http is used instead of fetch so that no keep-alive
// pool is left behind when a test finishes.
const request = (url, opts = {}) =>
    new Promise((resolve, reject) => {
        const req = http.request(
            url,
            {
                method: opts.method || 'GET',
                headers: Object.assign({ connection: 'close' }, opts.headers)
            },
            res => {
                const chunks = [];
                res.on('data', chunk => chunks.push(chunk));
                res.on('end', () =>
                    resolve({
                        status: res.statusCode,
                        headers: res.headers,
                        body: Buffer.concat(chunks).toString()
                    })
                );
            }
        );
        req.once('error', reject);
        req.end(opts.body);
    });

// Complete a TLS handshake and hand `read` the connected socket.
const tlsConnect = (opts, read) =>
    new Promise((resolve, reject) => {
        const socket = tls.connect(Object.assign({ host: '127.0.0.1', rejectUnauthorized: false }, opts), () => {
            const value = read(socket);
            socket.end();
            resolve(value);
        });
        socket.once('error', reject);
    });

// True while nothing is listening on the port.
const isPortFree = port =>
    new Promise(resolve => {
        const probe = http.createServer();
        probe.once('error', () => resolve(false));
        probe.listen(port, '127.0.0.1', () => probe.close(() => resolve(true)));
    });

module.exports = {
    DAY,
    acmeOptions,
    certKeyFor,
    closeDb,
    config,
    delay,
    flushTestDb,
    isPortFree,
    redisClient,
    request,
    seedCertificate,
    startAcmeDirectory,
    startRecordingServer,
    startServer,
    tlsConnect,
    useLocalDomainChecks,
    waitFor
};
