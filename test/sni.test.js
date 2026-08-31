'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const https = require('node:https');

const helpers = require('./helpers');
const { DAY, certKeyFor, closeDb, config, delay, flushTestDb, redisClient, startAcmeDirectory, tlsConnect } = helpers;
const { getSNIContext, defaultCtx, httpsCredentials, testables } = require('../lib/sni');

const { ctxCache } = testables;

// A real key pair is needed: tls.createSecureContext() parses whatever the SNI
// handler pulls out of Redis. The bundled default certificate is reused here.
const testKey = fs.readFileSync(config.https.key, 'utf-8');
const testCert = fs.readFileSync(config.https.cert, 'utf-8');

let directory;

const seedCertificate = (domain, expires) => helpers.seedCertificate(domain, { expires, key: testKey, cert: testCert });

test.before(async () => {
    await flushTestDb();
    // acme.init() runs before any certificate lookup, so it needs a directory
    // to fetch even when no certificate is ever ordered.
    directory = await startAcmeDirectory();
});

test.after(async () => {
    await directory.close();
    await closeDb();
});

test.beforeEach(() => {
    ctxCache.clear();
});

test('httpsCredentials carries the default certificate', () => {
    assert.equal(httpsCredentials.key, testKey);
    assert.equal(httpsCredentials.cert, testCert);
    assert.ok(httpsCredentials.dhparam, 'dh parameters loaded');
    assert.equal(httpsCredentials.sessionIdContext, config.https.sessionIdContext);
    assert.equal(typeof httpsCredentials.SNICallback, 'function');
});

test('a default secure context is built at startup', () => {
    assert.ok(defaultCtx);
    assert.equal(typeof defaultCtx.context, 'object');
});

test('getSNIContext rejects names that can not hold a certificate', async () => {
    assert.equal(await getSNIContext('not a domain'), false);
    assert.equal(await getSNIContext('localhost'), false);
    assert.equal(await getSNIContext('1.2.3.4'), false);
    assert.equal(await getSNIContext(''), false);
});

test('getSNIContext returns false when no certificate can be served', async () => {
    // The failsafe lock stands in for a recent provisioning failure. It keeps the
    // lookup local, so the test never reaches out to DNS or to an ACME server.
    const certKey = certKeyFor('unknown.example.com');
    await redisClient.set(`${certKey}:lock`, '1');

    assert.equal(await getSNIContext('unknown.example.com'), false);

    await redisClient.del(`${certKey}:lock`);
});

test('getSNIContext returns false for a certificate that has expired', async () => {
    const certKey = await seedCertificate('stale.example.com', Date.now() - DAY);
    await redisClient.set(`${certKey}:lock`, '1');

    assert.equal(await getSNIContext('stale.example.com'), false);

    await redisClient.del(certKey, `${certKey}:lock`);
});

test('getSNIContext builds a context from the stored certificate', async () => {
    const certKey = await seedCertificate('sni.example.com', Date.now() + 60 * DAY);

    const ctx = await getSNIContext('sni.example.com');
    assert.ok(ctx, 'context created');
    assert.equal(typeof ctx.context, 'object');

    await redisClient.del(certKey);
});

test('getSNIContext ignores the port in the server name', async () => {
    const certKey = await seedCertificate('port.example.com', Date.now() + 60 * DAY);

    assert.ok(await getSNIContext('port.example.com:443'));

    await redisClient.del(certKey);
});

test('a cached context is served without reading Redis again', async t => {
    const certKey = await seedCertificate('cache.example.com', Date.now() + 60 * DAY);

    const first = await getSNIContext('cache.example.com');
    assert.ok(first, 'context created');

    const reads = t.mock.method(redisClient, 'hgetall');
    const second = await getSNIContext('cache.example.com');

    assert.equal(second, first, 'the cached context was reused');
    assert.equal(reads.mock.callCount(), 0, 'no Redis lookup on a cache hit');

    await redisClient.del(certKey);
});

test('a renewed certificate is picked up once the check interval has passed', async () => {
    const certKey = await seedCertificate('renewed-ctx.example.com', Date.now() + 60 * DAY);

    const first = await getSNIContext('renewed-ctx.example.com');

    // a renewal gives the entry a new expiry
    await redisClient.hset(certKey, 'expires', new Date(Date.now() + 89 * DAY).toISOString());

    // still inside the check interval, so the old context is still served
    assert.equal(await getSNIContext('renewed-ctx.example.com'), first);

    await delay(config.https.contextCacheTtl * 1000 + 50);
    const third = await getSNIContext('renewed-ctx.example.com');
    assert.notEqual(third, first, 'the renewed certificate replaced the context');

    await redisClient.del(certKey);
});

test('an unchanged certificate keeps its context across a revalidation', async () => {
    const certKey = await seedCertificate('stable.example.com', Date.now() + 60 * DAY);

    const first = await getSNIContext('stable.example.com');
    await delay(config.https.contextCacheTtl * 1000 + 50);

    const second = await getSNIContext('stable.example.com');
    assert.equal(second, first, 'the context survived the revalidation');

    await redisClient.del(certKey);
});

test('a certificate that expires while cached is not served', async () => {
    // a long check interval, so only the expiry can invalidate the entry
    const originalTtl = config.https.contextCacheTtl;
    config.https.contextCacheTtl = 30;

    const certKey = await seedCertificate('expiring.example.com', Date.now() + 200);
    try {
        await getSNIContext('expiring.example.com');

        // the certificate lapses well inside the check interval
        await delay(250);
        await redisClient.set(`${certKey}:lock`, '1');

        assert.equal(await getSNIContext('expiring.example.com'), false, 'the expired context was dropped');
    } finally {
        config.https.contextCacheTtl = originalTtl;
        await redisClient.del(certKey, `${certKey}:lock`);
    }
});

test('a domain with no certificate is not looked up on every handshake', async t => {
    const certKey = certKeyFor('missing.example.com');
    await redisClient.set(`${certKey}:lock`, '1');

    assert.equal(await getSNIContext('missing.example.com'), false);

    const reads = t.mock.method(redisClient, 'hgetall');
    assert.equal(await getSNIContext('missing.example.com'), false);
    assert.equal(reads.mock.callCount(), 0, 'the miss was remembered');

    // and it is retried once the shorter miss interval has passed
    await delay(config.https.missingContextTtl * 1000 + 50);
    assert.equal(await getSNIContext('missing.example.com'), false);
    assert.ok(reads.mock.callCount() > 0, 'the lookup was retried');

    await redisClient.del(`${certKey}:lock`);
});

test('the cache is bounded and evicts the least recently used domain', async () => {
    const originalSize = config.https.contextCacheSize;
    config.https.contextCacheSize = 3;

    const certKeys = [];
    try {
        for (const name of ['one', 'two', 'three']) {
            certKeys.push(await seedCertificate(`${name}.example.com`, Date.now() + 60 * DAY));
            await getSNIContext(`${name}.example.com`);
        }
        assert.equal(ctxCache.size, 3);

        // touching the oldest entry makes it the most recently used one
        await getSNIContext('one.example.com');

        certKeys.push(await seedCertificate('four.example.com', Date.now() + 60 * DAY));
        await getSNIContext('four.example.com');

        assert.equal(ctxCache.size, 3, 'the cache stayed within its bound');
        assert.deepEqual([...ctxCache.keys()], ['three.example.com', 'one.example.com', 'four.example.com']);
    } finally {
        config.https.contextCacheSize = originalSize;
        await redisClient.del(...certKeys);
    }
});

test('SNICallback falls back to the default context for unknown names', async () => {
    const ctx = await new Promise((resolve, reject) => {
        httpsCredentials.SNICallback('not a domain', (err, value) => (err ? reject(err) : resolve(value)));
    });

    assert.equal(ctx, defaultCtx);
});

test('SNICallback hands out the domain context when one exists', async () => {
    const certKey = await seedCertificate('callback.example.com', Date.now() + 60 * DAY);

    const ctx = await new Promise((resolve, reject) => {
        httpsCredentials.SNICallback('callback.example.com', (err, value) => (err ? reject(err) : resolve(value)));
    });

    assert.ok(ctx);
    assert.notEqual(ctx, defaultCtx);

    await redisClient.del(certKey);
});

test('an HTTPS server built from the credentials completes a handshake', async () => {
    const certKey = await seedCertificate('handshake.example.com', Date.now() + 60 * DAY);

    const server = https.createServer(httpsCredentials, (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('secure');
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    try {
        const peer = await tlsConnect({ port, servername: 'handshake.example.com' }, socket => socket.getPeerCertificate());
        assert.ok(peer.subject, 'server presented a certificate');
    } finally {
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
        await redisClient.del(certKey);
    }
});
