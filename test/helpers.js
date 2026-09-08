'use strict';

// Shared helpers for the test suite. Tests must run with NODE_ENV=test so that
// config/test.toml points Redis at the dedicated test database (db 15), the
// servers at loopback ports and the logger at "silent".

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const tls = require('node:tls');

if (!process.env.NODE_ENV) {
    process.env.NODE_ENV = 'test';
}

const config = require('@zone-eu/wild-config');
const { redisClient } = require('../lib/db');
const { testables } = require('../lib/certs');
const legacy = require('../lib/legacy-certs').testables;

// The certificate store lib/certs.js works through. Built on first use, so this
// is a function rather than a value: a test file that never asks for a
// certificate never opens the connection the store keeps for its renewal lock.
const certs = () => testables.getCerts();

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

// The bundled self signed certificate, which stands in for everything an order
// would come back with. A real certificate is needed: it is parsed on the way
// into the store, and tls.createSecureContext() parses it again in sni.js.
const signedCert = fs.readFileSync(config.https.cert, 'utf-8');
const signedKey = fs.readFileSync(config.https.key, 'utf-8');
const chainCert = '-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----';

// What a successful order answers with.
const issueCertificate = async () => ({ cert: signedCert, chain: [chainCert] });

// Replaces the exchanges with the certificate authority, and the CAA lookup in
// front of them, with local answers. No test in the suite is allowed to reach
// either, which is also why the renewal information the store would otherwise
// ask for is answered here rather than left to fail.
const ACCOUNT_KID = 'https://acme.example.test/acme/acct/4711';

const stubAcme = (t, { order, caa } = {}) => {
    const acme = certs().acme;

    return {
        resolveCaa: t.mock.method(testables.resolver, 'resolveCaa', caa || (async () => [])),

        createAccount: t.mock.method(acme, 'createAccount', async () => ({ kid: ACCOUNT_KID, account: { status: 'valid', key: { kid: ACCOUNT_KID } } })),

        createCertificate: t.mock.method(
            acme,
            'createCertificate',
            order ||
                (async () => {
                    throw new Error('no certificate order was expected');
                })
        ),

        getRenewalInfo: t.mock.method(acme, 'getRenewalInfo', async () => {
            throw new Error('no renewal information');
        })
    };
};

// The keys lib/certs.js writes itself: the marker for a domain whose last
// attempt failed, the count behind it, the pool wide pause and the two budgets.
// Setting the marker is how a test keeps a lookup local, with no DNS query and
// no order.
const { blockKey, budgetKey, failureKey, pauseKey, pauseFailureKey } = testables;

// Merge `overrides` into a configuration section for one test. Returns a
// restore() that puts the section back as it was.
const useConfig = (path, overrides) => {
    const parts = path.split('.');
    const key = parts.pop();
    const parent = parts.reduce((node, part) => node[part], config);
    const original = parent[key];

    parent[key] = Object.assign({}, original, overrides);
    return () => {
        parent[key] = original;
    };
};

// Narrow the order and validation budgets for a test that is about admission
// control. The ones in config/test.toml are wide enough that no other test runs
// into them.
const useLimits = overrides => useConfig('acme.limits', overrides);

// Same, for the renewal pass, which config/test.toml leaves switched off so that
// it never orders underneath a test about something else.
const useRenewalSettings = overrides => useConfig('renewal', overrides);

// Budgets that refill too slowly to matter while a test runs, so that spends can
// be counted rather than raced. The bursts are left to the caller: those are
// what a test about a budget is actually setting.
const frozenBudget = overrides => useLimits(Object.assign({ ordersPerHour: 0.36, validationsPerMinute: 0.06 }, overrides));

// Writes a bucket the way the Lua script in lib/rate-limit.js reads it back,
// `ageMs` in the past, which is how a test stands at the edge of a budget, or at
// a point in its refill, without spending its way there a token at a time.
const seedBucket = async (key, tokens, ageMs = 0) => {
    const [seconds, micros] = await redisClient.time();
    const now = Number(seconds) * 1000 + Math.floor(Number(micros) / 1000);
    await redisClient.hmset(key, { tokens, updated: now - ageMs });
};

// The same, for one of the two budgets lib/certs.js keeps.
const setBudget = (name, tokens) => seedBucket(budgetKey(name), tokens);

// The domains an order stub was asked for, sorted, which is what a test that
// does not control the order within a batch can assert on.
const orderedDomains = createCertificate => createCertificate.mock.calls.map(call => call.arguments[0].domains[0]).sort();

// Store a certificate for `domain` that expires at `expires` after a lifetime of
// `lifetime`, which is what the renewal maths measures against.
const seedCertificate = async (
    domain,
    {
        expires,
        lifetime = 90 * DAY,
        cert = 'stored-cert',
        privateKey = 'stored-private-key',
        ca = ['stored-chain'],
        serialNumber = '01',
        fingerprint = 'AA:BB:CC'
    } = {}
) => {
    await certs().setCertificateData(domain, {
        domain,
        cert,
        ca,
        privateKey,
        status: 'valid',
        altNames: [domain],
        serialNumber,
        fingerprint,
        validFrom: new Date(expires - lifetime),
        validTo: new Date(expires),
        lastCheck: new Date(),
        lastError: null,
        // No test asks a certificate authority for renewal information. Recording
        // that there was none to be had keeps the renewal check off the network,
        // and leaves the decision to the lifetime rule.
        renewalInfo: { serialNumber, fetchedAt: new Date(), unavailable: true, retryAfter: null }
    });

    return domain;
};

// Due for renewal: a ninety day certificate with `daysLeft` to go is two thirds
// of the way through its lifetime once that is under thirty.
const seedDue = (domain, daysLeft = 20) => seedCertificate(domain, { expires: Date.now() + daysLeft * DAY });

// Nowhere near due: only a third of the lifetime has gone.
const seedFresh = domain => seedCertificate(domain, { expires: Date.now() + 60 * DAY });

// Stores an http-01 challenge the way an order in flight would, against the
// pending certificate record the challenge store expects to find.
const storeChallenge = async (domain, token, keyAuthorization) => {
    await certs().setCertificateData(domain, { domain, status: 'pending' });
    await certs().acmeChallenge.set({ challenge: { identifier: { value: domain }, token, keyAuthorization } });
};

// The Redis keys releases up to 1.4.x stored the ACME account and a certificate
// under, which lib/legacy-certs.js imports from.
const { accountKey: legacyAccountKey, accountSettingKey, certificateKey: legacyCertKey } = legacy;

const seedLegacyAccount = (key, kid) =>
    redisClient.hmset(legacyAccountKey(), {
        key,
        account: JSON.stringify(kid ? { status: 'valid', key: { kid } } : { status: 'valid' }),
        created: new Date().toISOString()
    });

const seedLegacyCertificate = (domain, { cert, key, expires, lifetime = 90 * DAY, chain = 'legacy-chain' }) =>
    redisClient.hmset(legacyCertKey(domain), {
        key,
        cert,
        chain,
        validFrom: new Date(expires - lifetime).toISOString(),
        expires: new Date(expires).toISOString(),
        dnsNames: JSON.stringify([domain]),
        issuer: 'Test CA',
        status: 'valid'
    });

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
    ACCOUNT_KID,
    DAY,
    accountSettingKey,
    blockKey,
    budgetKey,
    certs,
    chainCert,
    closeDb,
    config,
    delay,
    flushTestDb,
    failureKey,
    frozenBudget,
    isPortFree,
    issueCertificate,
    legacyAccountKey,
    legacyCertKey,
    logRecords,
    orderedDomains,
    pauseFailureKey,
    pauseKey,
    redisClient,
    request,
    seedBucket,
    seedCertificate,
    seedDue,
    seedFresh,
    setBudget,
    seedLegacyAccount,
    seedLegacyCertificate,
    signedCert,
    signedKey,
    startApplication,
    startRecordingServer,
    startServer,
    storeChallenge,
    stubAcme,
    tlsConnect,
    useConfig,
    useLimits,
    useLocalDomainChecks,
    useRenewalSettings,
    waitFor
};
