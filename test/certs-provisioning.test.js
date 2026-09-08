'use strict';

// Covers the certificate provisioning flow: the ACME account, the bookkeeping
// around an order, and the failure paths. The exchanges with the certificate
// authority are stubbed, so nothing here talks to one, but everything below them
// (key generation, the certificate store, locking, Redis) is real.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
    ACCOUNT_KID,
    DAY,
    accountSettingKey,
    blockKey,
    certs,
    chainCert,
    closeDb,
    config,
    flushTestDb,
    issueCertificate,
    redisClient,
    seedCertificate,
    signedCert,
    stubAcme,
    useLocalDomainChecks,
    waitFor
} = require('./helpers');
const { getCertificate, resolveChallenge } = require('../lib/certs');

let restoreDomainChecks;

const rateLimited = async () => {
    throw new Error('rate limited');
};

test.before(async () => {
    await flushTestDb();
});

test.after(async () => {
    await closeDb();
});

test.beforeEach(async () => {
    await flushTestDb();
    restoreDomainChecks = useLocalDomainChecks();
});

test.afterEach(() => restoreDomainChecks());

test('the ACME account is provisioned once and then reused', async t => {
    const { createAccount } = stubAcme(t, { order: issueCertificate });

    await getCertificate('account.example.com');

    assert.equal(createAccount.mock.callCount(), 1);
    assert.equal(createAccount.mock.calls[0].arguments[0].email, config.acme.email);

    // the account key is RSA, which is the store's default; only the
    // certificates this proxy orders are switched to P-256
    const stored = await certs().settings.get(accountSettingKey(certs()));
    assert.match(stored.privateKey, /^-----BEGIN RSA PRIVATE KEY-----/);
    assert.equal(stored.account.key.kid, ACCOUNT_KID);

    // the next order reads the account back rather than registering another one
    await getCertificate('second.example.com');
    assert.equal(createAccount.mock.callCount(), 1);
});

test('a new certificate is ordered and stored', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    const cert = await getCertificate('fresh.example.com');

    assert.equal(createCertificate.mock.callCount(), 1);
    const order = createCertificate.mock.calls[0].arguments[0];
    assert.deepEqual(order.domains, ['fresh.example.com']);
    assert.equal(order.kid, ACCOUNT_KID);

    // certificates are issued against a P-256 key, not an RSA one
    const certificateKey = crypto.createPrivateKey(order.certificateKey);
    assert.equal(certificateKey.asymmetricKeyType, 'ec');
    assert.equal(certificateKey.asymmetricKeyDetails.namedCurve, 'prime256v1');
    assert.ok(order.challenges['http-01'], 'the http-01 challenge store is wired up');

    assert.equal(cert.cert, signedCert);
    assert.deepEqual(cert.ca, [chainCert]);
    assert.equal(cert.status, 'valid');
    assert.ok(cert.validTo > new Date(), 'the issued certificate is still valid');
    assert.deepEqual(cert.altNames, ['https-front.local']);

    assert.deepEqual(await certs().listCertificateDomains(), ['fresh.example.com']);
});

test('the name that is validated is the name that is ordered', async t => {
    const { createCertificate, resolveCaa } = stubAcme(t, { order: issueCertificate });

    // This A-label decodes to a plain ASCII name, which is what the certificate
    // store files it under and what the order carries. Validating the spelling
    // that arrived would check a different domain than the one the certificate
    // ends up being issued for.
    await getCertificate('xn--ban-0k1a.app.example.com');

    assert.deepEqual(createCertificate.mock.calls[0].arguments[0].domains, ['bank.app.example.com']);
    assert.equal(resolveCaa.mock.calls[0].arguments[0], 'bank.app.example.com', 'the CAA records of the ordered name were the ones checked');
});

test('the challenge store an order is given is the one the HTTP handler reads', async t => {
    stubAcme(t, {
        order: async options => {
            // what the ACME client does once the authorization arrives
            await options.challenges['http-01'].set({
                challenge: { identifier: { value: 'challenge.example.com' }, token: 'a-token', keyAuthorization: 'a-token.key-authorization' }
            });
            return issueCertificate();
        }
    });

    await getCertificate('challenge.example.com');

    assert.equal(await resolveChallenge('challenge.example.com', 'a-token'), 'a-token.key-authorization');
});

test('the private key is reused when a certificate is renewed', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    await getCertificate('renewed.example.com');
    const originalKey = (await certs().getCertificate('renewed.example.com', true)).privateKey;
    assert.ok(originalKey, 'a private key was stored');

    // age the stored certificate into its renewal window without touching the
    // private key, which lives in a field of its own
    await certs().setCertificateData('renewed.example.com', {
        validFrom: new Date(Date.now() - 89 * DAY),
        validTo: new Date(Date.now() + DAY)
    });

    const cert = await getCertificate('renewed.example.com');
    assert.equal(cert.cert, signedCert, 'the certificate in place is served while the renewal runs');

    await waitFor(() => createCertificate.mock.callCount() === 2);
    assert.equal(createCertificate.mock.calls[1].arguments[0].certificateKey, originalKey);
    // a renewal names the certificate it replaces, which is how the CA counts it
    assert.equal(createCertificate.mock.calls[1].arguments[0].replaces, signedCert);
});

test('a failed order blocks retries and records the failure', async t => {
    const { createCertificate } = stubAcme(t, { order: rateLimited });

    await assert.rejects(() => getCertificate('failing.example.com'), /rate limited/);

    // the store keeps a failsafe lock of its own; this is the one that stops the
    // proxy from validating the domain again on the next handshake
    assert.equal(await redisClient.exists(blockKey('failing.example.com')), 1, 'renewal was blocked');
    const ttl = await redisClient.ttl(blockKey('failing.example.com'));
    assert.ok(ttl > 0 && ttl <= 300, `unexpected block ttl ${ttl}`);

    const stored = await certs().getCertificate('failing.example.com', true);
    assert.equal(stored.status, 'failed');
    assert.equal(stored.lastError.err, 'rate limited');
    assert.ok(!stored.cert, 'nothing was stored to serve');

    // the retry is skipped while the failsafe lock is in place
    const attemptsBefore = createCertificate.mock.callCount();
    const cert = await getCertificate('failing.example.com');
    assert.ok(!cert, 'nothing to serve');
    assert.equal(createCertificate.mock.callCount(), attemptsBefore);
});

test('a failed renewal keeps serving the certificate that is still valid', async t => {
    stubAcme(t, { order: rateLimited });

    // due for renewal, but the stored certificate has weeks of life left
    await seedCertificate('still-good.example.com', { expires: Date.now() + 20 * DAY });

    const cert = await getCertificate('still-good.example.com');
    assert.equal(cert.cert, 'stored-cert', 'the certificate in place is still served');

    // the renewal runs in the background, and gives up without touching what is
    // already in place
    await waitFor(() => redisClient.exists(blockKey('still-good.example.com')));

    const stored = await certs().getCertificate('still-good.example.com', true);
    assert.equal(stored.cert, 'stored-cert');
    assert.equal(stored.privateKey, 'stored-private-key');
    assert.equal(stored.lastError.err, 'rate limited');
});

// The detached renewal in getCertificate rejects here rather than falling back
// to the stored data. Its .catch is what keeps the rejection from escaping, so
// removing that catch makes this test fail with an unhandled rejection.
test('a background renewal that fails outright does not escape', async t => {
    stubAcme(t);
    t.mock.method(certs(), 'acquireCert', async () => {
        throw new Error('redis is unhappy');
    });

    await seedCertificate('background-fail.example.com', { expires: Date.now() + 20 * DAY });

    // the caller still gets the stored certificate, and nothing escapes
    const cert = await getCertificate('background-fail.example.com');
    assert.equal(cert.cert, 'stored-cert');

    await waitFor(() => certs().acquireCert.mock.callCount() > 0);
});

test('a burst of handshakes for one domain orders once', async t => {
    const { createCertificate } = stubAcme(t, {
        order: async () => {
            // slow enough that every caller in the burst is waiting on this order
            await new Promise(resolve => setTimeout(resolve, 50).unref());
            return issueCertificate();
        }
    });

    const certificates = await Promise.all(Array.from({ length: 5 }, () => getCertificate('burst.example.com')));

    assert.equal(createCertificate.mock.callCount(), 1, 'one order for the whole burst');
    assert.ok(
        certificates.every(cert => cert && cert.cert === signedCert),
        'every caller got the issued certificate'
    );
});
