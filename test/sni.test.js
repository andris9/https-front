'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const https = require('node:https');

const helpers = require('./helpers');
const { DAY, certKeyFor, closeDb, config, flushTestDb, redisClient, startAcmeDirectory, tlsConnect } = helpers;
const { getSNIContext, defaultCtx, httpsCredentials } = require('../lib/sni');

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

test('contexts are cached per domain until the certificate changes', async () => {
    const certKey = await seedCertificate('cache.example.com', Date.now() + 60 * DAY);

    const first = await getSNIContext('cache.example.com');
    const second = await getSNIContext('cache.example.com');
    assert.equal(first, second, 'cached context reused');

    // a renewed certificate has a new expiry, which must invalidate the cache
    await redisClient.hset(certKey, 'expires', new Date(Date.now() + 90 * DAY).toISOString());
    const third = await getSNIContext('cache.example.com');
    assert.notEqual(third, first, 'cache invalidated after renewal');

    await redisClient.del(certKey);
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
