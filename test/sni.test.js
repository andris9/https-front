'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const https = require('node:https');

const helpers = require('./helpers');
const { DAY, blockKey, closeDb, config, delay, flushTestDb, redisClient, tlsConnect } = helpers;
const { getSNIContext, defaultCtx, httpsCredentials, testables } = require('../lib/sni');

const { ctxCache, missCache, limits } = testables;

// A real key pair is needed: tls.createSecureContext() parses whatever the SNI
// handler pulls out of Redis. The bundled default certificate is reused here.
const testKey = fs.readFileSync(config.https.key, 'utf-8');
const testCert = fs.readFileSync(config.https.cert, 'utf-8');

const seedCertificate = (domain, expires, extra = {}) =>
    helpers.seedCertificate(domain, Object.assign({ expires, privateKey: testKey, cert: testCert, ca: [] }, extra));

test.before(async () => {
    await flushTestDb();
});

test.after(async () => {
    await closeDb();
});

test.beforeEach(() => {
    ctxCache.clear();
    missCache.clear();
});

test.afterEach(() => flushTestDb());

// Age a cached entry past its check interval, so the next lookup revalidates it
// without the test having to wait out the real interval.
const expireCacheEntry = domain => {
    const entry = ctxCache.get(domain) || missCache.get(domain);
    entry.checkAfter = Date.now() - 1;
};

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
    // The back-off marker stands in for a recent provisioning failure. It keeps
    // the lookup local, so the test never reaches out to DNS or to an ACME server.
    await redisClient.set(blockKey('unknown.example.com'), '1');

    assert.equal(await getSNIContext('unknown.example.com'), false);
});

test('getSNIContext returns false for a certificate that has expired', async () => {
    await seedCertificate('stale.example.com', Date.now() - DAY);
    await redisClient.set(blockKey('stale.example.com'), '1');

    assert.equal(await getSNIContext('stale.example.com'), false);
});

test('getSNIContext builds a context from the stored certificate', async () => {
    await seedCertificate('sni.example.com', Date.now() + 60 * DAY);

    const ctx = await getSNIContext('sni.example.com');
    assert.ok(ctx, 'context created');
    assert.equal(typeof ctx.context, 'object');
});

test('getSNIContext ignores the port in the server name', async () => {
    await seedCertificate('port.example.com', Date.now() + 60 * DAY);

    assert.ok(await getSNIContext('port.example.com:443'));
});

test('a cached context is served without reading Redis again', async t => {
    await seedCertificate('cache.example.com', Date.now() + 60 * DAY);

    const first = await getSNIContext('cache.example.com');
    assert.ok(first, 'context created');

    const reads = t.mock.method(redisClient, 'hmgetBuffer');
    const second = await getSNIContext('cache.example.com');

    assert.equal(second, first, 'the cached context was reused');
    assert.equal(reads.mock.callCount(), 0, 'no Redis lookup on a cache hit');
});

test('a renewed certificate is picked up once the check interval has passed', async () => {
    await seedCertificate('renewed-ctx.example.com', Date.now() + 60 * DAY);

    const first = await getSNIContext('renewed-ctx.example.com');

    // a renewal replaces the certificate, and with it the fingerprint the cached
    // context is matched against
    await seedCertificate('renewed-ctx.example.com', Date.now() + 89 * DAY, { serialNumber: '02', fingerprint: 'DD:EE:FF' });

    // still inside the check interval, so the old context is still served
    assert.equal(await getSNIContext('renewed-ctx.example.com'), first);

    expireCacheEntry('renewed-ctx.example.com');
    assert.notEqual(await getSNIContext('renewed-ctx.example.com'), first, 'the renewed certificate replaced the context');
});

test('an unchanged certificate keeps its context across a revalidation', async () => {
    await seedCertificate('stable.example.com', Date.now() + 60 * DAY);

    const first = await getSNIContext('stable.example.com');
    expireCacheEntry('stable.example.com');

    assert.equal(await getSNIContext('stable.example.com'), first, 'the context survived the revalidation');
});

test('a context is never served past the expiry of its certificate', async () => {
    await seedCertificate('expiring.example.com', Date.now() + 150);
    // blocked up front, so the lapsed certificate can not be renewed behind the test
    await redisClient.set(blockKey('expiring.example.com'), '1');

    await getSNIContext('expiring.example.com');

    // the check interval is clamped to the expiry rather than running past it
    assert.ok(ctxCache.get('expiring.example.com').checkAfter <= ctxCache.get('expiring.example.com').expires);

    await delay(200);
    assert.equal(await getSNIContext('expiring.example.com'), false, 'the expired context was dropped');
});

test('a domain with no certificate is not looked up on every handshake', async t => {
    await redisClient.set(blockKey('missing.example.com'), '1');

    assert.equal(await getSNIContext('missing.example.com'), false);

    const reads = t.mock.method(redisClient, 'hmgetBuffer');
    assert.equal(await getSNIContext('missing.example.com'), false);
    assert.equal(reads.mock.callCount(), 0, 'the miss was remembered');

    // and it is retried once the miss interval has passed
    expireCacheEntry('missing.example.com');
    assert.equal(await getSNIContext('missing.example.com'), false);
    assert.ok(reads.mock.callCount() > 0, 'the lookup was retried');
});

test('concurrent handshakes for one domain share a single lookup', async t => {
    await seedCertificate('burst.example.com', Date.now() + 60 * DAY);

    const reads = t.mock.method(redisClient, 'hmgetBuffer');
    const contexts = await Promise.all(Array.from({ length: 5 }, () => getSNIContext('burst.example.com')));

    assert.equal(reads.mock.callCount(), 1, 'one Redis lookup for the whole burst');
    assert.equal(new Set(contexts).size, 1, 'every handshake got the same context');
    assert.equal(ctxCache.size, 1);
});

test('a run of domains with no certificate does not evict the contexts being served', async () => {
    const originalSize = limits.cacheSize;
    limits.cacheSize = 2;

    try {
        await seedCertificate('served.example.com', Date.now() + 60 * DAY);
        const ctx = await getSNIContext('served.example.com');
        assert.ok(ctx, 'a context was built');

        // a scan working through names that have nothing stored
        for (let i = 0; i < 20; i++) {
            await redisClient.set(blockKey(`scan-${i}.example.com`), '1');
            assert.equal(await getSNIContext(`scan-${i}.example.com`), false);
        }

        assert.equal(ctxCache.size, 1, 'the misses went somewhere else');
        assert.equal(await getSNIContext('served.example.com'), ctx, 'the context that was being served survived the scan');
        assert.ok(missCache.size > 1, 'and the misses were still remembered');
    } finally {
        limits.cacheSize = originalSize;
    }
});

test('the misses are bounded too, so a scan cannot grow a worker without limit', async () => {
    const originalSize = limits.missCacheSize;
    limits.missCacheSize = 3;

    try {
        for (let i = 0; i < 10; i++) {
            await redisClient.set(blockKey(`bounded-${i}.example.com`), '1');
            await getSNIContext(`bounded-${i}.example.com`);
        }

        assert.equal(missCache.size, 3, 'the miss cache stayed within its bound');
    } finally {
        limits.missCacheSize = originalSize;
    }
});

test('the bound on the cache is the configured one', () => {
    // The number of domains a proxy fronts is what this has to be read against,
    // so it is a setting rather than an internal.
    assert.equal(limits.cacheSize, config.https.contextCacheSize);
    assert.ok(limits.cacheSize > 0);
});

test('the cache is bounded and evicts the least recently used domain', async () => {
    const originalSize = limits.cacheSize;
    limits.cacheSize = 3;

    try {
        for (const name of ['one', 'two', 'three']) {
            await seedCertificate(`${name}.example.com`, Date.now() + 60 * DAY);
            await getSNIContext(`${name}.example.com`);
        }
        assert.equal(ctxCache.size, 3);

        // touching the oldest entry makes it the most recently used one
        await getSNIContext('one.example.com');

        await seedCertificate('four.example.com', Date.now() + 60 * DAY);
        await getSNIContext('four.example.com');

        assert.equal(ctxCache.size, 3, 'the cache stayed within its bound');
        assert.deepEqual([...ctxCache.keys()], ['three.example.com', 'one.example.com', 'four.example.com']);
    } finally {
        limits.cacheSize = originalSize;
    }
});

test('SNICallback falls back to the default context for unknown names', async () => {
    const ctx = await new Promise((resolve, reject) => {
        httpsCredentials.SNICallback('not a domain', (err, value) => (err ? reject(err) : resolve(value)));
    });

    assert.equal(ctx, defaultCtx);
});

test('SNICallback hands out the domain context when one exists', async () => {
    await seedCertificate('callback.example.com', Date.now() + 60 * DAY);

    const ctx = await new Promise((resolve, reject) => {
        httpsCredentials.SNICallback('callback.example.com', (err, value) => (err ? reject(err) : resolve(value)));
    });

    assert.ok(ctx);
    assert.notEqual(ctx, defaultCtx);
});

test('an HTTPS server built from the credentials completes a handshake', async () => {
    await seedCertificate('handshake.example.com', Date.now() + 60 * DAY);

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
    }
});
