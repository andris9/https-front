'use strict';

// Covers the renewal pass in lib/renewal-sweeper.js: who runs it, how it walks
// the pool, what it decides is due and what it does when the order budget runs
// out underneath it. config/test.toml leaves the pass switched off, so every
// test here drives it directly rather than waiting for a timer.

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    certs,
    closeDb,
    config,
    delay,
    flushTestDb,
    frozenBudget,
    issueCertificate,
    orderedDomains,
    pauseKey,
    redisClient,
    seedDue,
    seedFresh,
    setBudget,
    stubAcme,
    useLocalDomainChecks,
    useRenewalSettings
} = require('./helpers');
const sweeper = require('../lib/renewal-sweeper');

const { INSTANCE_ID, collectDue, leaseKey, nextSlice, runPass, settings, takeLease, tick, reset } = sweeper.testables;

let restoreDomainChecks;
let restoreRenewal = () => false;
let restoreLimits = () => false;

test.before(async () => {
    await flushTestDb();
});

test.after(async () => {
    sweeper.stop();
    await closeDb();
});

test.beforeEach(async () => {
    await flushTestDb();
    reset();
    restoreDomainChecks = useLocalDomainChecks();
});

test.afterEach(() => {
    sweeper.stop();
    restoreDomainChecks();
    restoreRenewal();
    restoreLimits();
    restoreRenewal = () => false;
    restoreLimits = () => false;
});

test('one worker takes the lease and the others are turned away', async () => {
    assert.equal(await takeLease(), true, 'nobody held it');
    assert.equal(await redisClient.get(leaseKey()), INSTANCE_ID);

    // another worker holds it now
    await redisClient.set(leaseKey(), 'another-worker', 'EX', 180);
    assert.equal(await takeLease(), false, 'the pass belongs to whoever holds the lease');

    // and once this worker holds it again, it extends rather than fails
    await redisClient.set(leaseKey(), INSTANCE_ID, 'EX', 5);
    assert.equal(await takeLease(), true);
    assert.ok((await redisClient.ttl(leaseKey())) > 5, 'the lease was extended rather than left to run out');
});

test('the pool is walked one slice at a time, and the walk starts again at the end', async () => {
    for (const domain of ['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com', 'e.example.com']) {
        await seedFresh(domain);
    }

    assert.equal((await nextSlice(2)).length, 2);
    assert.equal((await nextSlice(2)).length, 2);
    assert.equal((await nextSlice(2)).length, 1, 'the last slice is whatever is left');

    // the pool is read again rather than the pass ending
    assert.equal((await nextSlice(2)).length, 2, 'a new pass started');
});

test('only certificates that are actually due are picked up, most urgent first', async () => {
    await seedDue('later.example.com', 25);
    await seedDue('sooner.example.com', 5);
    await seedDue('middle.example.com', 15);
    await seedFresh('fresh.example.com');

    // a record an order never finished writing a certificate into, and one that
    // has no record at all
    await certs().setCertificateData('pending.example.com', { domain: 'pending.example.com', cert: null, status: 'pending' });

    const due = await collectDue([
        'later.example.com',
        'sooner.example.com',
        'middle.example.com',
        'fresh.example.com',
        'pending.example.com',
        'gone.example.com'
    ]);

    assert.deepEqual(due, ['sooner.example.com', 'middle.example.com', 'later.example.com']);
});

test('a record that cannot be read is stepped over rather than ending the pass', async t => {
    await seedDue('readable.example.com');

    const readRecord = certs().getCertificate.bind(certs());
    t.mock.method(certs(), 'getCertificate', async (domain, skipAcquire) => {
        if (domain === 'broken.example.com') {
            throw new Error('redis is unhappy');
        }
        return readRecord(domain, skipAcquire);
    });

    const due = await collectDue(['broken.example.com', 'readable.example.com']);
    assert.deepEqual(due, ['readable.example.com'], 'the rest of the slice was still looked at');
});

test('a pass renews what is due and leaves what is not', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    await seedDue('due-one.example.com', 10);
    await seedDue('due-two.example.com', 20);
    await seedFresh('fresh.example.com');

    await runPass();

    assert.deepEqual(orderedDomains(createCertificate), ['due-one.example.com', 'due-two.example.com']);
});

test('a pass stops as soon as the order budget runs out, and keeps its place', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });
    restoreRenewal = useRenewalSettings({ concurrency: 1 });
    restoreLimits = frozenBudget({ orderBurst: 10 });

    await seedDue('urgent.example.com', 2);
    await seedDue('patient.example.com', 25);

    // enough for exactly one order, and refilling too slowly to matter
    await setBudget('orders', 1);

    await runPass();

    assert.deepEqual(orderedDomains(createCertificate), ['urgent.example.com'], 'the budget went to the certificate with the least life left');
});

test('a pass does nothing at all while the pool is paused', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    await seedDue('paused.example.com');
    await redisClient.set(pauseKey(), 1, 'EX', 900);

    await runPass();

    assert.equal(createCertificate.mock.callCount(), 0);
});

test('a pass does not start when there is no order budget to spend', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });
    restoreLimits = frozenBudget({ orderBurst: 10 });

    await seedDue('broke.example.com');
    await setBudget('orders', 0);

    await runPass();

    assert.equal(createCertificate.mock.callCount(), 0);
});

test('a renewal that fails does not stop the rest of the slice', async t => {
    const { createCertificate } = stubAcme(t, {
        order: async options => {
            if (options.domains[0] === 'broken.example.com') {
                throw new Error('the CA is having a moment');
            }
            return issueCertificate();
        }
    });
    restoreRenewal = useRenewalSettings({ concurrency: 1 });

    await seedDue('broken.example.com', 2);
    await seedDue('working.example.com', 25);

    await runPass();

    assert.deepEqual(orderedDomains(createCertificate), ['broken.example.com', 'working.example.com']);
    const working = await certs().getCertificate('working.example.com', true);
    assert.equal(working.status, 'valid', 'the domain after the failure was still renewed');
});

test('a renewal that rejects outright is logged and the pass carries on', async t => {
    stubAcme(t, { order: issueCertificate });
    restoreRenewal = useRenewalSettings({ concurrency: 1 });

    await seedDue('unreadable.example.com', 2);
    await seedDue('fine.example.com', 25);

    // Not a failed order but a failed attempt at one, which acquireCert rethrows
    // rather than turning into a record. Nothing above renewAll() catches it.
    const acquire = certs().acquireCert.bind(certs());
    t.mock.method(certs(), 'acquireCert', async domain => {
        if (domain === 'unreadable.example.com') {
            throw new Error('redis is unhappy');
        }
        return acquire(domain);
    });

    await runPass();

    const fine = await certs().getCertificate('fine.example.com', true);
    assert.equal(fine.status, 'valid', 'the domain after the rejection was still renewed');
});

test('a slice with nothing due in it orders nothing', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    await seedFresh('one.example.com');
    await seedFresh('two.example.com');

    await runPass();

    assert.equal(createCertificate.mock.callCount(), 0);
});

test('a tick that overruns the interval skips the next one rather than stacking up', async t => {
    const list = t.mock.method(certs(), 'listCertificateDomains', async () => {
        await delay(50);
        return [];
    });

    await Promise.all([tick(), tick(), tick()]);

    assert.equal(list.mock.callCount(), 1, 'only one pass ran');
});

test('a tick does nothing, and holds on to nothing, when another worker has the lease', async t => {
    const list = t.mock.method(certs(), 'listCertificateDomains', async () => ['held.example.com']);

    // read a slice while this worker still holds the lease, then lose it
    await nextSlice(1);
    await redisClient.set(leaseKey(), 'another-worker', 'EX', 180);

    await tick();

    assert.equal(list.mock.callCount(), 1, 'no pass ran');
    // the pool this worker was walking is not held for as long as it lives
    assert.equal((await nextSlice(1)).length, 1);
    assert.equal(list.mock.callCount(), 2, 'the walk started again from the beginning');
});

test('a pass that throws is reported rather than escaping the tick', async t => {
    const list = t.mock.method(certs(), 'listCertificateDomains', async () => {
        throw new Error('redis is unhappy');
    });

    // resolves rather than rejecting, and the next tick is still willing to try
    await tick();
    await tick();

    assert.equal(list.mock.callCount(), 2, 'a failed pass does not stop the next one');
});

test('the timer is only started when renewals are switched on, and only once', async () => {
    restoreRenewal = useRenewalSettings({ enabled: false });
    assert.equal(sweeper.start(), false, 'switched off in the configuration');

    restoreRenewal();
    restoreRenewal = useRenewalSettings({ enabled: true, interval: 3600 });

    assert.equal(sweeper.start(), true);
    assert.equal(sweeper.start(), false, 'a second call does not start a second timer');

    sweeper.stop();
    assert.equal(sweeper.start(), true, 'and it can be started again once stopped');
});

test('unusable settings fall back to the defaults rather than to zero', () => {
    restoreRenewal = useRenewalSettings({ interval: 0, batchSize: -1, concurrency: 'nonsense' });

    const resolved = settings();
    assert.ok(resolved.interval > 0, `unexpected interval ${resolved.interval}`);
    assert.ok(resolved.batchSize > 0, `unexpected batch size ${resolved.batchSize}`);
    assert.ok(resolved.concurrency > 0, `unexpected concurrency ${resolved.concurrency}`);
});

test('a configuration with no renewal block at all still renews', () => {
    const original = config.renewal;
    delete config.renewal;

    try {
        const resolved = settings();
        assert.equal(resolved.enabled, true, 'renewing is what this does unless it is switched off');
        assert.ok(resolved.interval > 0 && resolved.batchSize > 0 && resolved.concurrency > 0);
    } finally {
        config.renewal = original;
    }
});
