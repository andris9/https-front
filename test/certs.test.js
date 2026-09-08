'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    DAY,
    blockKey,
    closeDb,
    config,
    delay,
    flushTestDb,
    redisClient,
    seedCertificate,
    startRecordingServer,
    stubAcme,
    useLocalDomainChecks
} = require('./helpers');
const { getCertificate, testables } = require('../lib/certs');

const { isUsable, validateDomain, resolver } = testables;

// No test in this file orders an actual certificate.
let restoreDomainChecks;

test.before(async () => {
    await flushTestDb();
});

test.after(async () => {
    await closeDb();
});

test('isUsable', async t => {
    const stored = (expires, extra = {}) => Object.assign({ cert: 'stored-cert', privateKey: 'stored-private-key', validTo: new Date(expires) }, extra);

    await t.test('accepts a certificate that has not expired', () => {
        assert.equal(isUsable(stored(Date.now() + DAY)), true);
    });

    await t.test('rejects an expired certificate', () => {
        assert.equal(isUsable(stored(Date.now() - DAY)), false);
    });

    await t.test('rejects a record that can not be served', () => {
        // a record with a key but no certificate is what an order that has not
        // finished yet looks like
        assert.equal(isUsable({ privateKey: 'stored-private-key', validTo: new Date(Date.now() + DAY) }), false);
        assert.equal(isUsable({ cert: 'stored-cert', validTo: new Date(Date.now() + DAY) }), false);
        assert.equal(isUsable(stored('not a date')), false);
        assert.equal(isUsable({ cert: 'stored-cert', privateKey: 'stored-private-key' }), false);
        assert.equal(isUsable(false), false);
        assert.equal(isUsable(null), false);
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
    t.beforeEach(async () => {
        await flushTestDb();
        restoreDomainChecks = useLocalDomainChecks();
    });

    t.afterEach(() => restoreDomainChecks());

    await t.test('returns a stored certificate that is not due for renewal', async () => {
        await seedCertificate('cached.example.com', { expires: Date.now() + 60 * DAY });

        const cert = await getCertificate('cached.example.com');

        assert.equal(cert.cert, 'stored-cert');
        assert.equal(cert.privateKey, 'stored-private-key');
        assert.deepEqual(cert.ca, ['stored-chain']);
        assert.ok(cert.validTo instanceof Date);
        assert.deepEqual(cert.altNames, ['cached.example.com']);
    });

    await t.test('normalizes the requested domain name', async () => {
        await seedCertificate('unicode.example.com', { expires: Date.now() + 60 * DAY });

        const cert = await getCertificate('  Unicode.Example.COM ');
        assert.equal(cert.cert, 'stored-cert');
    });

    await t.test('serves a certificate that is close to expiry and renews in the background', async t2 => {
        const order = stubAcme(t2).createCertificate;
        await seedCertificate('renew.example.com', { expires: Date.now() + 10 * DAY });
        // A recent failure makes the background renewal a no-op, so the test
        // never reaches out to a certificate authority.
        await redisClient.set(blockKey('renew.example.com'), '1');

        const cert = await getCertificate('renew.example.com');
        assert.equal(cert.cert, 'stored-cert');

        // give the detached renewal a chance to run
        await delay(25);
        assert.equal(order.mock.callCount(), 0, 'the back-off blocked the order');
    });

    await t.test('serves no certificate for an expired entry while renewal is blocked', async () => {
        await seedCertificate('expired.example.com', { expires: Date.now() - DAY });
        await redisClient.set(blockKey('expired.example.com'), '1');

        // Renewal is blocked after a recent failure. The stored certificate has
        // already expired, so nothing usable is returned and the SNI handler
        // falls back to the default certificate.
        const cert = await getCertificate('expired.example.com');
        assert.ok(!cert, 'no usable certificate');
    });

    await t.test('remembers a validation failure instead of retrying it on every request', async t2 => {
        const caa = stubAcme(t2, { caa: async () => [{ issue: 'digicert.com' }] }).resolveCaa;

        assert.ok(!(await getCertificate('blocked-caa.example.com')));

        // recorded in Redis, so every worker and instance backs off
        assert.equal(await redisClient.exists(blockKey('blocked-caa.example.com')), 1, 'renewal was blocked');

        const ttl = await redisClient.ttl(blockKey('blocked-caa.example.com'));
        assert.ok(ttl > 0 && ttl <= 300, `unexpected block ttl ${ttl}`);

        // and the retry costs no DNS queries while the marker is in place
        const before = caa.mock.callCount();
        assert.ok(!(await getCertificate('blocked-caa.example.com')));
        assert.equal(caa.mock.callCount(), before, 'validation was not repeated');
    });

    await t.test('does not revalidate a domain whose last attempt failed', async t2 => {
        const { resolveCaa, createCertificate } = stubAcme(t2);
        await redisClient.set(blockKey('order-failed.example.com'), '1');

        assert.ok(!(await getCertificate('order-failed.example.com')));
        assert.equal(resolveCaa.mock.callCount(), 0, 'the back-off was checked before the DNS queries');
        assert.equal(createCertificate.mock.callCount(), 0, 'and before anything was ordered');
    });

    await t.test('gives up on a domain that fails validation', async t2 => {
        stubAcme(t2, { caa: async () => [{ issue: 'digicert.com' }] });

        // no stored data, and validation fails, so there is nothing to serve
        const cert = await getCertificate('invalid-caa.example.com');
        assert.ok(!cert, 'no certificate for a domain that fails validation');
    });

    await t.test('refuses a name that can not hold a certificate without touching Redis', async t2 => {
        const reads = t2.mock.method(redisClient, 'hmgetBuffer');

        assert.equal(await getCertificate('not a domain'), false);
        assert.equal(await getCertificate('localhost'), false);
        assert.equal(reads.mock.callCount(), 0);
    });
});
