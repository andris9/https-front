'use strict';

// Covers the certificate provisioning flow: ACME account handling, the Redis
// bookkeeping around a renewal, and the failure paths. The ACME client itself is
// stubbed, so nothing here talks to a certificate authority, but everything
// below it (key generation, CSR building, locking, Redis storage) is real.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const { DAY, acmeOptions, certKeyFor, closeDb, config, flushTestDb, redisClient, startAcmeDirectory, useLocalDomainChecks } = require('./helpers');
const { getCertificate, testables } = require('../lib/certs');

const { acme, resolver } = testables;

const signedCert = fs.readFileSync(config.https.cert, 'utf-8');

let directory;
let restoreDomainChecks;

test.before(async () => {
    await flushTestDb();
    directory = await startAcmeDirectory();
});

test.after(async () => {
    await directory.close();
    await closeDb();
});

test.beforeEach(async () => {
    await flushTestDb();
    restoreDomainChecks = useLocalDomainChecks();
});

test.afterEach(() => restoreDomainChecks());

test('the ACME account is provisioned once and then reused', async t => {
    const created = [];
    t.mock.method(acme.accounts, 'create', async options => {
        created.push(options);
        return { key: { kid: `${directory.url}/acme/acct/4711` } };
    });

    const first = await testables.getAcmeAccount(acmeOptions());
    assert.equal(created.length, 1);
    assert.equal(created[0].subscriberEmail, config.acme.email);
    assert.equal(created[0].agreeToTerms, true);
    assert.equal(created[0].accountKey.kty, 'RSA');
    assert.match(first.key, /^-----BEGIN RSA PRIVATE KEY-----/);

    const stored = await redisClient.hgetall(`acme:account:${config.acme.key}`);
    assert.ok(stored.key, 'account key stored');
    assert.ok(stored.created, 'creation timestamp stored');

    // second call must come from Redis
    const second = await testables.getAcmeAccount(acmeOptions());
    assert.equal(created.length, 1);
    assert.equal(second.key, first.key);
    assert.deepEqual(second.account, first.account);
    assert.ok(second.created instanceof Date);
});

test('a corrupted ACME account entry is reported instead of silently reused', async t => {
    t.mock.method(acme.accounts, 'create', async () => {
        throw new Error('should not be called');
    });

    await redisClient.hmset(`acme:account:${config.acme.key}`, { key: 'stored-key', account: 'not json' });

    await assert.rejects(() => testables.getAcmeAccount(acmeOptions()), /Failed to retrieve ACME account/);
});

test('a new certificate is ordered and stored in Redis', async t => {
    t.mock.method(resolver, 'resolveCaa', async () => []);
    t.mock.method(acme.accounts, 'create', async () => ({ key: { kid: `${directory.url}/acme/acct/4711` } }));

    const orders = [];
    t.mock.method(acme.certificates, 'create', async options => {
        orders.push(options);
        return { cert: signedCert, chain: '-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----' };
    });

    const cert = await getCertificate(acmeOptions(), 'fresh.example.com');

    assert.equal(orders.length, 1);
    assert.deepEqual(orders[0].domains, ['fresh.example.com']);
    assert.match(orders[0].csr, /^-----BEGIN CERTIFICATE REQUEST-----/);
    assert.ok(orders[0].challenges['http-01'], 'the http-01 challenge handler is wired up');

    assert.equal(cert.cert, signedCert);
    assert.equal(cert.status, 'valid');
    assert.ok(cert.expires instanceof Date);
    assert.ok(cert.expires > new Date(), 'the issued certificate is still valid');

    const certKey = certKeyFor('fresh.example.com');
    const stored = await redisClient.hgetall(certKey);
    assert.match(stored.key, /^-----BEGIN RSA PRIVATE KEY-----/);
    assert.equal(stored.issuer, 'https-front.local');

    // the Redis entry expires together with the certificate
    const ttl = await redisClient.ttl(certKey);
    assert.ok(ttl > 0, `unexpected ttl ${ttl}`);
});

test('the private key is reused when a certificate is renewed', async t => {
    t.mock.method(resolver, 'resolveCaa', async () => []);
    t.mock.method(acme.accounts, 'create', async () => ({ key: { kid: `${directory.url}/acme/acct/4711` } }));
    t.mock.method(acme.certificates, 'create', async () => ({ cert: signedCert, chain: 'chain' }));

    const certKey = certKeyFor('renewed.example.com');

    await getCertificate(acmeOptions(), 'renewed.example.com');
    const originalKey = await redisClient.hget(certKey, 'key');

    // pretend the stored certificate is about to expire, then ask again
    await redisClient.hset(certKey, 'expires', new Date(Date.now() - DAY).toISOString());
    await getCertificate(acmeOptions(), 'renewed.example.com');

    assert.equal(await redisClient.hget(certKey, 'key'), originalKey);
});

test('a failed order blocks retries and leaves no certificate behind', async t => {
    t.mock.method(resolver, 'resolveCaa', async () => []);
    t.mock.method(acme.accounts, 'create', async () => ({ key: { kid: `${directory.url}/acme/acct/4711` } }));
    t.mock.method(acme.certificates, 'create', async () => {
        throw new Error('rate limited');
    });

    await assert.rejects(() => getCertificate(acmeOptions(), 'failing.example.com'), /rate limited/);

    const certKey = certKeyFor('failing.example.com');
    assert.equal(await redisClient.exists(`${certKey}:lock`), 1, 'failsafe lock was set');

    const ttl = await redisClient.ttl(`${certKey}:lock`);
    assert.ok(ttl > 3500 && ttl <= 3600, `unexpected lock ttl ${ttl}`);

    // the retry is skipped while the failsafe lock is in place
    const attemptsBefore = acme.certificates.create.mock.callCount();
    const cert = await getCertificate(acmeOptions(), 'failing.example.com');
    assert.ok(!cert, 'nothing to serve');
    assert.equal(acme.certificates.create.mock.callCount(), attemptsBefore);
});

test('an unusable stored private key fails the renewal and blocks retries', async t => {
    t.mock.method(resolver, 'resolveCaa', async () => []);
    t.mock.method(acme.accounts, 'create', async () => ({ key: { kid: `${directory.url}/acme/acct/4711` } }));

    const certKey = certKeyFor('broken-key.example.com');
    await redisClient.hset(certKey, 'key', 'not a private key');

    await assert.rejects(() => getCertificate(acmeOptions(), 'broken-key.example.com'));

    // The key is rejected while it is converted to a JWK, which happens before
    // the CSR step that knows how to drop a broken key, so the entry survives and
    // only the failsafe lock stops the retry loop. Keys are only ever written by
    // generateKey(), so this is a defensive path rather than a reachable one.
    assert.equal(await redisClient.hexists(certKey, 'key'), 1);
    assert.equal(await redisClient.exists(`${certKey}:lock`), 1, 'failsafe lock was set');
});

test('an empty ACME response yields nothing to serve and is not stored', async t => {
    t.mock.method(resolver, 'resolveCaa', async () => []);
    t.mock.method(acme.accounts, 'create', async () => ({ key: { kid: `${directory.url}/acme/acct/4711` } }));
    t.mock.method(acme.certificates, 'create', async () => ({}));

    const cert = await getCertificate(acmeOptions(), 'empty.example.com');
    assert.ok(!cert, 'nothing usable to serve');

    const stored = await redisClient.hgetall(certKeyFor('empty.example.com'));
    assert.equal(stored.cert, undefined);
});

test('a certificate renewed by another worker is not ordered twice', async t => {
    t.mock.method(resolver, 'resolveCaa', async () => []);
    t.mock.method(acme.accounts, 'create', async () => ({ key: { kid: `${directory.url}/acme/acct/4711` } }));
    t.mock.method(acme.certificates, 'create', async () => {
        throw new Error('should not be called');
    });

    // an expired entry, so the lookup goes all the way into the renewal path
    const certKey = certKeyFor('raced.example.com');
    await redisClient.hmset(certKey, {
        cert: 'stored-cert',
        chain: 'stored-chain',
        expires: new Date(Date.now() - DAY).toISOString()
    });

    // while the renewal lock is being acquired, another worker finishes the job
    const original = redisClient.hgetall.bind(redisClient);
    t.mock.method(redisClient, 'hgetall', async key => {
        if (key === certKey) {
            t.mock.restoreAll();
            await redisClient.hset(certKey, 'expires', new Date(Date.now() + 60 * DAY).toISOString());
        }
        return original(key);
    });

    const cert = await getCertificate(acmeOptions(), 'raced.example.com');
    assert.equal(cert.cert, 'stored-cert');
});
