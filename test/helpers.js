'use strict';

// Shared helpers for the test suite. Tests must run with NODE_ENV=test so that
// config/test.toml points Redis at the dedicated test database (db 15), the
// servers at loopback ports and the logger at "silent".

const { spawn } = require('node:child_process');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const tls = require('node:tls');

if (!process.env.NODE_ENV) {
    process.env.NODE_ENV = 'test';
}

const config = require('@zone-eu/wild-config');
const { redisClient } = require('../lib/db');
const { certificateKey } = require('../lib/certs').testables;

const DAY = 24 * 3600 * 1000;

const delay = ms =>
    new Promise(resolve => {
        // unref'd, so a pending delay never keeps the test process alive
        setTimeout(resolve, ms).unref();
    });

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

// Start an HTTP server on a loopback port, random unless one is given. Returns
// the server, its port and its base URL, plus a close() that resolves once the
// port is free again. Passing a port and no handler makes it a port blocker.
const startServer = (handler, port = 0) =>
    new Promise((resolve, reject) => {
        const server = http.createServer(handler);
        server.once('error', reject);
        server.listen(port, '127.0.0.1', () => {
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
        const transport = url.startsWith('https:') ? https : http;
        const req = transport.request(
            url,
            {
                method: opts.method || 'GET',
                // the default certificate is self signed, and no test verifies it
                rejectUnauthorized: false,
                servername: opts.servername,
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

// The application logs newline delimited JSON, so assertions read records
// rather than matching text across an ever growing buffer.
const logRecords = output =>
    output
        .split('\n')
        .filter(Boolean)
        .flatMap(line => {
            try {
                return [JSON.parse(line)];
            } catch {
                // ioredis and Node warnings share the stream and are not JSON
                return [];
            }
        });

// Boots the real entry point the way the Dockerfile does. Resolves once the
// child logs something matching `ready`, which is "Server started" for a healthy
// boot and a failure message for the tests that exercise a broken one. The child
// is stopped and its ports released when the test that started it ends.
const startApplication = async (t, { env = {}, ready = /Server started/ } = {}) => {
    const child = spawn(process.execPath, ['server.js'], {
        cwd: path.join(__dirname, '..'),
        // the child needs real logs: the assertions read its output
        env: Object.assign({}, process.env, { NODE_ENV: 'test', appconf_log_level: 'info' }, env),
        stdio: ['ignore', 'pipe', 'pipe']
    });

    let output = '';
    let failure = null;
    const waiters = new Set();

    const settle = () => {
        for (const waiter of [...waiters]) {
            if (failure) {
                waiters.delete(waiter);
                clearTimeout(waiter.timer);
                waiter.reject(failure);
            } else if (waiter.pattern.test(output)) {
                waiters.delete(waiter);
                clearTimeout(waiter.timer);
                waiter.resolve(output);
            }
        }
    };

    const onData = chunk => {
        output += chunk.toString();
        settle();
    };

    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.once('error', err => {
        failure = err;
        settle();
    });

    // Resolves once the child has logged something matching `pattern`, off the
    // stream itself rather than by polling the accumulated output.
    const waitForLog = (pattern, { timeout = 10000 } = {}) =>
        new Promise((resolve, reject) => {
            if (failure) {
                return reject(failure);
            }
            if (pattern.test(output)) {
                return resolve(output);
            }
            const waiter = { pattern, resolve, reject };
            waiter.timer = setTimeout(() => {
                waiters.delete(waiter);
                reject(new Error(`Timed out waiting for ${pattern}. Output:\n${output}`));
            }, timeout);
            waiters.add(waiter);
        });

    const stop = signal =>
        new Promise(done => {
            if (child.exitCode !== null) {
                return done({ code: child.exitCode });
            }
            // 'close' rather than 'exit', so the last log lines are read before
            // the result is inspected
            child.once('close', (code, sig) => done({ code, signal: sig }));
            child.kill(signal || 'SIGTERM');
        });

    t.after(async () => {
        // SIGTERM first: the child writes its coverage profile on a clean exit
        child.kill('SIGTERM');
        await waitFor(() => child.exitCode !== null, { timeout: 2000 });
        await stop('SIGKILL');
        await waitFor(() => isPortFree(config.http.port), { timeout: 10000 });
        await waitFor(() => isPortFree(config.https.port), { timeout: 10000 });
    });

    await waitForLog(ready, { timeout: 20000 });

    return { child, output: () => output, records: () => logRecords(output), stop, waitForLog };
};

module.exports = {
    DAY,
    acmeOptions,
    certKeyFor,
    closeDb,
    config,
    delay,
    flushTestDb,
    isPortFree,
    logRecords,
    redisClient,
    request,
    seedCertificate,
    startAcmeDirectory,
    startApplication,
    startRecordingServer,
    startServer,
    tlsConnect,
    useLocalDomainChecks,
    waitFor
};
