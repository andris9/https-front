'use strict';

// Covers the certificate provisioning flow: ACME account handling, the Redis
// bookkeeping around a renewal, and the failure paths. The ACME client itself is
// stubbed, so nothing here talks to a certificate authority, but everything
// below it (key generation, CSR building, locking, Redis storage) is real.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const {
    DAY,
    acmeOptions,
    certKeyFor,
    closeDb,
    config,
    flushTestDb,
    redisClient,
    seedCertificate,
    startAcmeDirectory,
    useLocalDomainChecks,
    waitFor
} = require('./helpers');
const { getCertificate, testables } = require('../lib/certs');

const CSR = require('@root/csr');

const { acme, resolver } = testables;

const signedCert = fs.readFileSync(config.https.cert, 'utf-8');

let directory;
let restoreDomainChecks;

// Domain validation passes and the ACME account resolves, so each test only has
// to say how the certificate order itself behaves.
const stubAcme = (t, order) => {
    t.mock.method(resolver, 'resolveCaa', async () => []);
    t.mock.method(acme.accounts, 'create', async () => ({ key: { kid: `${directory.url}/acme/acct/4711` } }));
    return order ? t.mock.method(acme.certificates, 'create', order) : undefined;
};

const rateLimited = async () => {
    throw new Error('rate limited');
};

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
    const orders = [];
    stubAcme(t, async options => {
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
    stubAcme(t, async () => ({ cert: signedCert, chain: 'chain' }));

    const certKey = certKeyFor('renewed.example.com');

    await getCertificate(acmeOptions(), 'renewed.example.com');
    const originalKey = await redisClient.hget(certKey, 'key');

    // pretend the stored certificate is about to expire, then ask again
    await redisClient.hset(certKey, 'expires', new Date(Date.now() - DAY).toISOString());
    await getCertificate(acmeOptions(), 'renewed.example.com');

    assert.equal(await redisClient.hget(certKey, 'key'), originalKey);
});

test('a failed order blocks retries and leaves no certificate behind', async t => {
    stubAcme(t, rateLimited);

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
    stubAcme(t);

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
    stubAcme(t, async () => ({}));

    const cert = await getCertificate(acmeOptions(), 'empty.example.com');
    assert.ok(!cert, 'nothing usable to serve');

    const stored = await redisClient.hgetall(certKeyFor('empty.example.com'));
    assert.equal(stored.cert, undefined);
});

test('a CSR that can not be built drops the stored key', async t => {
    t.mock.method(resolver, 'resolveCaa', async () => []);
    t.mock.method(CSR, 'csr', async () => {
        throw new Error('bad csr');
    });

    const certKey = certKeyFor('csr-fail.example.com');

    await assert.rejects(() => getCertificate(acmeOptions(), 'csr-fail.example.com'), /bad csr/);

    // no live certificate depended on that key, so the entry is thrown away and
    // the next attempt starts from a clean slate
    assert.equal(await redisClient.exists(certKey), 0, 'the entry was dropped');
    assert.equal(await redisClient.exists(`${certKey}:lock`), 1, 'renewal was blocked');
});

test('a cleanup Redis refuses does not mask the CSR failure', async t => {
    t.mock.method(resolver, 'resolveCaa', async () => []);
    t.mock.method(CSR, 'csr', async () => {
        throw new Error('bad csr');
    });
    t.mock.method(redisClient, 'del', async () => {
        throw new Error('redis is unhappy');
    });

    // the CSR error is what the caller sees, not the failed cleanup
    await assert.rejects(() => getCertificate(acmeOptions(), 'cleanup-fail.example.com'), /bad csr/);
});

test('a broken ACME client drops the stored key too', async t => {
    stubAcme(t, async () => {
        throw new TypeError('cannot read properties of undefined');
    });

    const certKey = certKeyFor('typeerror.example.com');

    await assert.rejects(() => getCertificate(acmeOptions(), 'typeerror.example.com'), TypeError);

    assert.equal(await redisClient.exists(certKey), 0, 'the entry was dropped');
});

test('a failed renewal keeps serving the certificate that is still valid', async t => {
    stubAcme(t, rateLimited);

    // due for renewal, but the stored certificate has weeks of life left
    const certKey = await seedCertificate('still-good.example.com', { expires: Date.now() + 20 * DAY });
    // an expired-looking entry would be dropped, so aim straight at acquireCert
    await redisClient.hset(certKey, 'validFrom', new Date(Date.now() - 70 * DAY).toISOString());

    const cert = await getCertificate(acmeOptions(), 'still-good.example.com');
    assert.equal(cert.cert, 'stored-cert', 'the certificate in place is still served');

    // the renewal runs in the background, and gives up without touching what is
    // already in place
    await waitFor(() => redisClient.exists(`${certKey}:lock`));
    assert.equal(await redisClient.hget(certKey, 'cert'), 'stored-cert');
    assert.equal(await redisClient.hexists(certKey, 'key'), 1);
});

test('a Redis failure while recording the failsafe does not mask the original error', async t => {
    stubAcme(t, rateLimited);
    t.mock.method(redisClient, 'set', async () => {
        throw new Error('redis is unhappy');
    });

    await assert.rejects(() => getCertificate(acmeOptions(), 'lock-fail.example.com'), /rate limited/);
});

// The detached renewal in getCertificate rejects here rather than falling back
// to the stored data. Its .catch is what keeps the rejection from escaping, so
// removing that catch makes this test fail with an unhandled rejection.
test('a background renewal that fails outright does not escape', async t => {
    const certKey = await seedCertificate('background-fail.example.com', { expires: Date.now() + 20 * DAY });
    await redisClient.hset(certKey, 'validFrom', new Date(Date.now() - 70 * DAY).toISOString());

    // the detached renewal rejects before it can fall back to the stored data
    const exists = redisClient.exists.bind(redisClient);
    t.mock.method(redisClient, 'exists', async key => {
        if (key === `${certKey}:lock`) {
            throw new Error('redis is unhappy');
        }
        return exists(key);
    });

    // the caller still gets the stored certificate, and nothing escapes
    const cert = await getCertificate(acmeOptions(), 'background-fail.example.com');
    assert.equal(cert.cert, 'stored-cert');
});

test('a certificate renewed by another worker is not ordered twice', async t => {
    t.mock.method(resolver, 'resolveCaa', async () => []);
    t.mock.method(acme.accounts, 'create', async () => ({ key: { kid: `${directory.url}/acme/acct/4711` } }));
    const order = t.mock.method(acme.certificates, 'create', async () => {
        throw new Error('should not be called');
    });

    // an expired entry, so the lookup goes all the way into the renewal path
    const certKey = certKeyFor('raced.example.com');
    await redisClient.hmset(certKey, {
        key: 'stored-private-key',
        cert: 'stored-cert',
        chain: 'stored-chain',
        expires: new Date(Date.now() - DAY).toISOString()
    });

    // The second read is the one taken after the renewal lock has been acquired.
    // Another worker finishes the renewal just before it.
    const original = redisClient.hgetall.bind(redisClient);
    let reads = 0;
    t.mock.method(redisClient, 'hgetall', async key => {
        if (key === certKey && ++reads === 2) {
            await redisClient.hmset(certKey, {
                cert: 'renewed-cert',
                validFrom: new Date(Date.now() - DAY).toISOString(),
                expires: new Date(Date.now() + 89 * DAY).toISOString()
            });
        }
        return original(key);
    });

    const cert = await getCertificate(acmeOptions(), 'raced.example.com');
    assert.equal(cert.cert, 'renewed-cert', 'the certificate the other worker stored is used');
    assert.equal(order.mock.callCount(), 0, 'nothing was ordered');
});
