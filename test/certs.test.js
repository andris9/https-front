'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { pem2jwk } = require('pem-jwk');

const {
    DAY,
    acmeOptions,
    closeDb,
    config,
    delay,
    flushTestDb,
    redisClient,
    seedCertificate,
    startAcmeDirectory,
    startRecordingServer,
    useLocalDomainChecks
} = require('./helpers');
const { getCertificate, testables } = require('../lib/certs');

const { generateKey, formatCertificateData, validateDomain, resolver } = testables;

// No test in this file orders an actual certificate.
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

// Runs first on purpose: the ACME directory is fetched once per process, so this
// is the only chance to observe the initialization itself.
test('concurrent lookups initialize the ACME client only once', async () => {
    const certKey = await seedCertificate('init.example.com', { expires: Date.now() + 60 * DAY });

    const before = directory.requestCount();
    await Promise.all([
        getCertificate(acmeOptions(), 'init.example.com'),
        getCertificate(acmeOptions(), 'init.example.com'),
        getCertificate(acmeOptions(), 'init.example.com')
    ]);

    assert.equal(directory.requestCount() - before, 1);
    await redisClient.del(certKey);
});

test('generateKey', async t => {
    await t.test('returns a PKCS#1 RSA private key PEM', async () => {
        const pem = await generateKey(2048);
        assert.match(pem, /^-----BEGIN RSA PRIVATE KEY-----/);
        assert.match(pem, /-----END RSA PRIVATE KEY-----\s*$/);

        const keyObject = crypto.createPrivateKey(pem);
        assert.equal(keyObject.asymmetricKeyType, 'rsa');
        assert.equal(keyObject.asymmetricKeyDetails.modulusLength, 2048);
    });

    await t.test('defaults to a 2048 bit key', async () => {
        const keyObject = crypto.createPrivateKey(await generateKey());
        assert.equal(keyObject.asymmetricKeyDetails.modulusLength, 2048);
    });

    await t.test('converts to a JWK via pem-jwk, as the ACME flow needs', async () => {
        const jwk = pem2jwk(await generateKey(2048));
        assert.equal(jwk.kty, 'RSA');
        assert.ok(jwk.n, 'modulus present');
        assert.ok(jwk.d, 'private exponent present');
    });
});

test('formatCertificateData', async t => {
    await t.test('returns false for missing data', () => {
        assert.equal(formatCertificateData(null), false);
        assert.equal(formatCertificateData(undefined), false);
        assert.equal(formatCertificateData(''), false);
    });

    await t.test('parses the stored date strings', () => {
        const formatted = formatCertificateData({
            validFrom: '2023-01-01T00:00:00.000Z',
            expires: '2023-04-01T00:00:00.000Z',
            lastCheck: '2023-02-01T00:00:00.000Z',
            created: '2023-01-01T00:00:00.000Z'
        });

        for (const key of ['validFrom', 'expires', 'lastCheck', 'created']) {
            assert.ok(formatted[key] instanceof Date, `${key} is a Date`);
        }
        assert.equal(formatted.expires.toISOString(), '2023-04-01T00:00:00.000Z');
    });

    await t.test('parses the dnsNames JSON list', () => {
        const formatted = formatCertificateData({ dnsNames: '["example.com","www.example.com"]' });
        assert.deepEqual(formatted.dnsNames, ['example.com', 'www.example.com']);
    });

    await t.test('marks unparseable dnsNames as false', () => {
        assert.equal(formatCertificateData({ dnsNames: 'not json' }).dnsNames, false);
    });

    await t.test('leaves other values untouched', () => {
        const formatted = formatCertificateData({ cert: 'pem', issuer: 'Test CA' });
        assert.equal(formatted.cert, 'pem');
        assert.equal(formatted.issuer, 'Test CA');
    });
});

test('validateDomain', async t => {
    t.beforeEach(() => {
        restoreDomainChecks = useLocalDomainChecks();
    });

    t.afterEach(() => restoreDomainChecks());

    await t.test('rejects an invalid domain name and names it in the error', async () => {
        await assert.rejects(() => validateDomain('not a domain'), { code: 'invalid_domain', message: /not a domain/ });
    });

    await t.test('accepts a domain when no extra checks are configured', async t2 => {
        t2.mock.method(resolver, 'resolveCaa', async () => []);
        assert.equal(await validateDomain('example.com'), true);
    });

    await t.test('rejects a domain whose CAA record excludes Let’s Encrypt', async t2 => {
        t2.mock.method(resolver, 'resolveCaa', async () => [{ issue: 'digicert.com' }]);

        await assert.rejects(() => validateDomain('example.com'), { code: 'caa_mismatch' });
    });

    await t.test('accepts a domain whose CAA record allows Let’s Encrypt', async t2 => {
        t2.mock.method(resolver, 'resolveCaa', async () => [{ issue: ' LetsEncrypt.ORG ' }]);
        assert.equal(await validateDomain('example.com'), true);
    });

    await t.test('walks up the labels until a CAA record is found', async t2 => {
        const queried = [];
        t2.mock.method(resolver, 'resolveCaa', async name => {
            queried.push(name);
            return name === 'example.com' ? [{ issue: 'letsencrypt.org' }] : [];
        });

        assert.equal(await validateDomain('deep.sub.example.com'), true);
        assert.deepEqual(queried, ['deep.sub.example.com', 'sub.example.com', 'example.com']);
    });

    await t.test('ignores CAA lookup failures', async t2 => {
        t2.mock.method(resolver, 'resolveCaa', async () => {
            throw new Error('ENOTFOUND');
        });
        assert.equal(await validateDomain('example.com'), true);
    });

    await t.test('rejects wildcard DNS when wildcards are not allowed', async t2 => {
        config.extraChecks = { wildCardAllowed: false };
        t2.mock.method(resolver, 'resolveCaa', async () => []);
        t2.mock.method(resolver, 'resolve4', async () => ['1.2.3.4']);

        await assert.rejects(() => validateDomain('sub.example.com'), { code: 'wildcard_dns' });
    });

    await t.test('accepts a subdomain when the wildcard probe does not resolve', async t2 => {
        config.extraChecks = { wildCardAllowed: false };
        t2.mock.method(resolver, 'resolveCaa', async () => []);
        t2.mock.method(resolver, 'resolve4', async () => {
            const err = new Error('queryA ENOTFOUND');
            err.code = 'ENOTFOUND';
            throw err;
        });

        assert.equal(await validateDomain('sub.example.com'), true);
    });

    await t.test('does not probe for wildcards on a registrable domain', async t2 => {
        config.extraChecks = { wildCardAllowed: false };
        t2.mock.method(resolver, 'resolveCaa', async () => []);
        const resolve4 = t2.mock.method(resolver, 'resolve4', async () => ['1.2.3.4']);

        assert.equal(await validateDomain('example.com'), true);
        assert.equal(resolve4.mock.callCount(), 0);
    });

    await t.test('passes when a precheck record matches', async t2 => {
        config.precheck = [{ key: 'A', expected: '1.2.3.4' }];
        t2.mock.method(resolver, 'resolveCaa', async () => []);
        t2.mock.method(resolver, 'resolve4', async () => ['5.6.7.8', '1.2.3.4']);

        assert.equal(await validateDomain('example.com'), true);
    });

    await t.test('fails when no precheck record matches', async t2 => {
        config.precheck = [{ key: 'A', expected: '1.2.3.4' }];
        t2.mock.method(resolver, 'resolveCaa', async () => []);
        t2.mock.method(resolver, 'resolve4', async () => ['9.9.9.9']);

        await assert.rejects(() => validateDomain('example.com'), { code: 'precheck_failed' });
    });

    await t.test('fails when a precheck lookup returns nothing', async t2 => {
        config.precheck = [{ key: 'CNAME', expected: 'front.example.net' }];
        t2.mock.method(resolver, 'resolveCaa', async () => []);
        t2.mock.method(resolver, 'resolveCname', async () => []);

        await assert.rejects(() => validateDomain('example.com'), { code: 'precheck_failed' });
    });

    await t.test('fails when a precheck lookup errors', async t2 => {
        config.precheck = [{ key: 'AAAA', expected: '::1' }];
        t2.mock.method(resolver, 'resolveCaa', async () => []);
        t2.mock.method(resolver, 'resolve6', async () => {
            throw new Error('SERVFAIL');
        });

        await assert.rejects(() => validateDomain('example.com'), { code: 'precheck_failed' });
    });

    await t.test('rejects an unsupported precheck record type', async t2 => {
        config.precheck = [{ key: 'BOGUS', expected: 'x' }];
        t2.mock.method(resolver, 'resolveCaa', async () => []);

        await assert.rejects(() => validateDomain('example.com'), { code: 'unknown_rr_type' });
    });

    await t.test('runs the configured validation URL', async t2 => {
        t2.mock.method(resolver, 'resolveCaa', async () => []);

        const endpoint = await startRecordingServer({ body: '{"success":true}', contentType: 'application/json' });

        config.checkUrl = {
            enabled: true,
            url: `${endpoint.url}/validate`,
            method: 'get',
            key: 'domain',
            expect: { status: [200] }
        };

        try {
            assert.equal(await validateDomain('example.com'), true);
            assert.deepEqual(
                endpoint.received.map(req => req.url),
                ['/validate?domain=example.com']
            );
        } finally {
            await endpoint.close();
        }
    });

    await t.test('fails when the validation URL rejects the domain', async t2 => {
        t2.mock.method(resolver, 'resolveCaa', async () => []);

        const endpoint = await startRecordingServer({ body: '{"success":false}', contentType: 'application/json' });

        config.checkUrl = {
            enabled: true,
            url: `${endpoint.url}/validate`,
            method: 'get',
            key: 'domain',
            expect: { key: 'success', value: true }
        };

        try {
            await assert.rejects(() => validateDomain('example.com'), /Invalid value success=false/);
        } finally {
            await endpoint.close();
        }
    });
});

test('getCertificate', async t => {
    await t.test('returns a stored certificate that is not due for renewal', async () => {
        const certKey = await seedCertificate('cached.example.com', { expires: Date.now() + 60 * DAY });

        const cert = await getCertificate(acmeOptions(), 'cached.example.com');

        assert.equal(cert.cert, 'stored-cert');
        assert.equal(cert.chain, 'stored-chain');
        assert.ok(cert.expires instanceof Date);
        assert.deepEqual(cert.dnsNames, ['cached.example.com']);

        await redisClient.del(certKey);
    });

    await t.test('normalizes the requested domain name', async () => {
        const certKey = await seedCertificate('unicode.example.com', { expires: Date.now() + 60 * DAY });

        const cert = await getCertificate(acmeOptions(), '  Unicode.Example.COM ');
        assert.equal(cert.cert, 'stored-cert');

        await redisClient.del(certKey);
    });

    await t.test('serves a certificate that is close to expiry and renews in the background', async () => {
        const certKey = await seedCertificate('renew.example.com', { expires: Date.now() + 10 * DAY });
        // The failsafe lock makes the background renewal a no-op, so the test
        // never reaches out to the ACME directory.
        await redisClient.set(`${certKey}:lock`, '1');

        const cert = await getCertificate(acmeOptions(), 'renew.example.com');
        assert.equal(cert.cert, 'stored-cert');

        // give the detached renewal a chance to run
        await delay(25);
        assert.equal(await redisClient.hget(certKey, 'cert'), 'stored-cert');

        await redisClient.del(certKey, `${certKey}:lock`);
    });

    await t.test('serves no certificate for an expired entry while the failsafe lock is set', async () => {
        const certKey = await seedCertificate('expired.example.com', { expires: Date.now() - DAY });
        await redisClient.set(`${certKey}:lock`, '1');

        // The failsafe lock blocks renewal for an hour after a failure. The stored
        // certificate has already expired, so nothing usable is returned and the
        // SNI handler falls back to the default certificate.
        const cert = await getCertificate(acmeOptions(), 'expired.example.com');
        assert.ok(!cert, 'no usable certificate');

        await redisClient.del(certKey, `${certKey}:lock`);
    });

    await t.test('gives up on a domain that fails validation', async t2 => {
        const restore = useLocalDomainChecks();
        t2.mock.method(resolver, 'resolveCaa', async () => [{ issue: 'digicert.com' }]);

        try {
            // no stored data, and validation fails, so there is nothing to serve
            const cert = await getCertificate(acmeOptions(), 'invalid-caa.example.com');
            assert.ok(!cert, 'no certificate for a domain that fails validation');
        } finally {
            restore();
        }
    });
});
