'use strict';

// Renewal scheduling. Let's Encrypt is cutting certificate lifetimes from 90 to
// 64 days (2027-02-10) and then to 45 days (2028-02-16), so renewal is driven by
// a fraction of each certificate's own lifetime rather than by a fixed "30 days
// left" window. The rule itself lives in @postalsys/certs; what is asserted here
// is what this proxy does with it.
// https://letsencrypt.org/2025/12/02/from-90-to-45

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    DAY,
    blockKey,
    certs,
    closeDb,
    delay,
    flushTestDb,
    issueCertificate,
    redisClient,
    seedCertificate,
    stubAcme,
    useLocalDomainChecks,
    waitFor
} = require('./helpers');
const { getCertificate } = require('../lib/certs');

let restoreDomainChecks;

// A stored certificate of `lifetime` days that is `age` days old.
const seedAged = (domain, lifetime, age) => seedCertificate(domain, { expires: Date.now() + (lifetime - age) * DAY, lifetime: lifetime * DAY });

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

test('a certificate is renewed once two thirds of its lifetime has passed', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    const cases = [
        { lifetime: 90, age: 30, due: false },
        { lifetime: 90, age: 61, due: true },
        // the case the old fixed 30 day window got wrong: a 45 day certificate
        // that is only 20 days old still has 25 days of life left, and must not
        // be pushed into a renewal loop
        { lifetime: 45, age: 20, due: false },
        { lifetime: 45, age: 31, due: true },
        { lifetime: 64, age: 40, due: false },
        { lifetime: 64, age: 44, due: true }
    ];

    for (const { lifetime, age, due } of cases) {
        await t.test(`${lifetime} day certificate, ${age} days old`, async () => {
            const domain = `lifetime-${lifetime}-age-${age}.example.com`;
            await seedAged(domain, lifetime, age);

            const before = createCertificate.mock.callCount();
            const cert = await getCertificate(domain);
            assert.equal(cert.cert, 'stored-cert', 'the stored certificate is served either way');

            if (due) {
                await waitFor(() => createCertificate.mock.callCount() > before);
            } else {
                // nothing to wait for, so give a renewal that should not happen
                // a chance to happen anyway
                await delay(25);
            }

            assert.equal(createCertificate.mock.callCount() > before, due, due ? 'a renewal was ordered' : 'nothing was ordered');
        });
    }
});

test('a blocked renewal keeps serving the certificate in place', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    await seedAged('blocked.example.com', 90, 61);
    await redisClient.set(blockKey('blocked.example.com'), '1');

    // renewal is due and blocked, but the stored certificate is still valid, so
    // it has to be handed back rather than falling through to the default one
    const cert = await getCertificate('blocked.example.com');
    assert.equal(cert.cert, 'stored-cert');

    await delay(25);
    assert.equal(createCertificate.mock.callCount(), 0, 'the back-off blocked the order');
});

test('a domain that stops validating keeps its current certificate until it expires', async t => {
    // the domain no longer passes validation, so no renewal is possible
    const { createCertificate } = stubAcme(t, { caa: async () => [{ issue: 'digicert.com' }] });

    await seedAged('unvalidated.example.com', 90, 61);

    const cert = await getCertificate('unvalidated.example.com');
    assert.equal(cert.cert, 'stored-cert');

    await waitFor(() => redisClient.exists(blockKey('unvalidated.example.com')));
    assert.equal(createCertificate.mock.callCount(), 0, 'nothing was ordered for a domain that fails validation');

    const stored = await certs().getCertificate('unvalidated.example.com', true);
    assert.equal(stored.cert, 'stored-cert', 'the certificate in place was left alone');
});

test('an expired certificate is never handed back', async t => {
    stubAcme(t, { order: issueCertificate });

    await seedAged('gone.example.com', 90, 91);
    await redisClient.set(blockKey('gone.example.com'), '1');

    const cert = await getCertificate('gone.example.com');
    assert.ok(!cert, 'nothing usable to serve');
});
