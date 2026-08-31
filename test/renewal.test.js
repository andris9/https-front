'use strict';

// Renewal scheduling. Let's Encrypt is cutting certificate lifetimes from 90 to
// 64 days (2027-02-10) and then to 45 days (2028-02-16), so renewal has to be
// driven by a fraction of each certificate's own lifetime rather than by a fixed
// "30 days left" window. https://letsencrypt.org/2025/12/02/from-90-to-45

const test = require('node:test');
const assert = require('node:assert/strict');

const helpers = require('./helpers');
const { DAY, acmeOptions, closeDb, delay, flushTestDb, redisClient, startAcmeDirectory, useLocalDomainChecks } = helpers;
const { getCertificate, testables } = require('../lib/certs');

const { needsRenewal, renewalTime, isUsable, acme, resolver } = testables;

let directory;

// A certificate of `lifetime` that is `age` old.
const certificate = (lifetime, age, extra = {}) =>
    Object.assign(
        {
            cert: 'stored-cert',
            validFrom: new Date(Date.now() - age),
            expires: new Date(Date.now() - age + lifetime)
        },
        extra
    );

// A stored certificate of `lifetime` that is `age` old.
const seedCertificate = (domain, lifetime, age) => helpers.seedCertificate(domain, { expires: Date.now() - age + lifetime, lifetime });

test.before(async () => {
    await flushTestDb();
    directory = await startAcmeDirectory();
});

test.after(async () => {
    await directory.close();
    await closeDb();
});

test('renewalTime lands two thirds into the lifetime, whatever the lifetime is', async t => {
    // Let's Encrypt today, from 2027-02-10, and from 2028-02-16
    for (const lifetime of [90, 64, 45]) {
        await t.test(`${lifetime} day certificate`, () => {
            const data = certificate(lifetime * DAY, 0);
            const expected = data.validFrom.getTime() + Math.round(lifetime * DAY * (2 / 3));

            // within a second, the clock moves while the test runs
            assert.ok(Math.abs(renewalTime(data) - expected) < 1000, `renewalTime for a ${lifetime} day certificate`);

            // and that is the same as "a third of the lifetime left"
            const remaining = data.expires.getTime() - renewalTime(data);
            assert.ok(Math.abs(remaining - (lifetime * DAY) / 3) < 1000, `${remaining / DAY} days remaining at renewal`);
        });
    }
});

test('a certificate is renewed only once two thirds of its lifetime has passed', async t => {
    const cases = [
        { lifetime: 90, age: 30, due: false },
        { lifetime: 90, age: 59, due: false },
        { lifetime: 90, age: 61, due: true },
        // the case the old fixed 30 day window got wrong: a 45 day certificate
        // that is only 20 days old still has 25 days of life left, and must not
        // be pushed into a renewal loop
        { lifetime: 45, age: 20, due: false },
        { lifetime: 45, age: 29, due: false },
        { lifetime: 45, age: 31, due: true },
        { lifetime: 64, age: 40, due: false },
        { lifetime: 64, age: 44, due: true }
    ];

    for (const { lifetime, age, due } of cases) {
        await t.test(`${lifetime} day certificate, ${age} days old`, () => {
            assert.equal(needsRenewal(certificate(lifetime * DAY, age * DAY)), due);
        });
    }
});

test('needsRenewal treats an entry without a certificate as due', () => {
    assert.equal(needsRenewal(null), true);
    assert.equal(needsRenewal(undefined), true);
    assert.equal(needsRenewal({}), true);
    assert.equal(needsRenewal({ key: 'only-a-private-key' }), true);
});

test('needsRenewal treats an entry with no usable expiry as due', () => {
    assert.equal(needsRenewal({ cert: 'stored-cert' }), true);
    assert.equal(needsRenewal({ cert: 'stored-cert', expires: 'not a date' }), true);
});

test('a missing or nonsensical validFrom falls back to the longest lifetime', () => {
    // no validFrom: a 90 day lifetime is assumed, which renews early rather than
    // late, so renewal is due with less than 30 days left
    assert.equal(needsRenewal({ cert: 'stored-cert', expires: new Date(Date.now() + 40 * DAY) }), false);
    assert.equal(needsRenewal({ cert: 'stored-cert', expires: new Date(Date.now() + 20 * DAY) }), true);

    // validFrom after expires is meaningless and gets the same treatment
    const backwards = {
        cert: 'stored-cert',
        validFrom: new Date(Date.now() + 30 * DAY),
        expires: new Date(Date.now() + 10 * DAY)
    };
    assert.equal(needsRenewal(backwards), true);
});

test('isUsable accepts a valid certificate and rejects an expired one', () => {
    assert.equal(isUsable(certificate(90 * DAY, 89 * DAY)), true);

    assert.equal(isUsable(certificate(90 * DAY, 91 * DAY)), false);
    assert.equal(isUsable({ cert: 'stored-cert' }), false);
    assert.equal(isUsable({ expires: new Date(Date.now() + DAY) }), false);
    assert.equal(isUsable({}), false);
    assert.equal(isUsable(null), false);
});

test('a short lived certificate is served without renewing on every request', async t => {
    // a 45 day certificate, 20 days in: the old rule renewed anything with less
    // than 30 days left, which for these lifetimes is almost always
    const certKey = await seedCertificate('short.example.com', 45 * DAY, 20 * DAY);

    t.mock.method(resolver, 'resolveCaa', async () => []);
    const order = t.mock.method(acme.certificates, 'create', async () => {
        throw new Error('should not be called');
    });

    const cert = await getCertificate(acmeOptions(), 'short.example.com');
    assert.equal(cert.cert, 'stored-cert');

    // nothing was ordered, and no failsafe lock was set by a failed attempt
    await delay(25);
    assert.equal(order.mock.callCount(), 0);
    assert.equal(await redisClient.exists(`${certKey}:lock`), 0);

    await redisClient.del(certKey);
});

test('a short lived certificate past two thirds of its life is renewed in the background', async t => {
    const certKey = await seedCertificate('due.example.com', 45 * DAY, 31 * DAY);
    // the failsafe lock keeps the background renewal from reaching out to ACME
    await redisClient.set(`${certKey}:lock`, '1');

    t.mock.method(resolver, 'resolveCaa', async () => []);
    const order = t.mock.method(acme.certificates, 'create', async () => {
        throw new Error('should not be called');
    });

    // the stored certificate is still served while the renewal runs
    const cert = await getCertificate(acmeOptions(), 'due.example.com');
    assert.equal(cert.cert, 'stored-cert');

    await delay(25);
    assert.equal(order.mock.callCount(), 0, 'the failsafe lock blocked the order');

    await redisClient.del(certKey, `${certKey}:lock`);
});

test('a blocked renewal keeps serving the certificate that is already in place', async () => {
    const certKey = await seedCertificate('blocked.example.com', 90 * DAY, 61 * DAY);
    await redisClient.set(`${certKey}:lock`, '1');

    // renewal is due and blocked, but the stored certificate is still valid, so
    // it has to be handed back rather than falling through to the default one
    const cert = await getCertificate(acmeOptions(), 'blocked.example.com');
    assert.ok(cert, 'the stored certificate is still served');
    assert.equal(cert.cert, 'stored-cert');

    await redisClient.del(certKey, `${certKey}:lock`);
});

test('a domain that stops validating keeps its current certificate until it expires', async t => {
    const certKey = await seedCertificate('unvalidated.example.com', 90 * DAY, 61 * DAY);

    // the domain no longer passes validation, so no renewal is possible
    t.mock.method(resolver, 'resolveCaa', async () => [{ issue: 'digicert.com' }]);
    const restore = useLocalDomainChecks();

    try {
        const cert = await getCertificate(acmeOptions(), 'unvalidated.example.com');
        assert.equal(cert.cert, 'stored-cert');
    } finally {
        restore();
        await redisClient.del(certKey);
    }
});

test('an expired certificate is never handed back', async () => {
    const certKey = await seedCertificate('gone.example.com', 90 * DAY, 91 * DAY);
    await redisClient.set(`${certKey}:lock`, '1');

    const cert = await getCertificate(acmeOptions(), 'gone.example.com');
    assert.ok(!cert, 'nothing usable to serve');

    await redisClient.del(certKey, `${certKey}:lock`);
});
