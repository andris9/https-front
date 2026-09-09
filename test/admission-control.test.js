'use strict';

// Covers what lib/certs.js will and will not start an order for: the two budgets
// an attempt is admitted through, the pool wide stop after the certificate
// authority reports a rate limit, and how long a domain is left alone after a
// failure. The exchanges with the CA are stubbed, as everywhere else in the
// suite, so nothing here talks to one.

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    blockKey,
    certs,
    closeDb,
    config,
    failureKey,
    flushTestDb,
    frozenBudget,
    issueCertificate,
    pauseFailureKey,
    pauseKey,
    orderedDomains,
    redisClient,
    seedDue,
    seedFresh,
    seedStoreLock,
    setBudget,
    stubAcme,
    useLocalDomainChecks
} = require('./helpers');
const { getCertificate, renew, testables } = require('../lib/certs');

const { BLOCK_NO_BUDGET_TTL, BLOCK_RENEW_AFTER_FAILURE_TTL, BLOCK_RENEW_MAX_TTL, RATE_LIMITED } = testables;

let restoreDomainChecks;
let restoreLimits = () => false;

// What the certificate authority answers with once the account is over a limit.
const rateLimitedOrder = async () => {
    const err = new Error('[429] too many new orders');
    err.type = RATE_LIMITED;
    throw err;
};

// Any other answer from the CA, which arms the store's own hour long failsafe.
const serverError = async () => {
    const err = new Error('[500] the CA is having a moment');
    err.type = 'urn:ietf:params:acme:error:serverInternal';
    throw err;
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

test.afterEach(() => {
    restoreDomainChecks();
    restoreLimits();
    restoreLimits = () => false;
});

test('a first issuance is refused once the order budget is down to the renewal reserve', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });
    restoreLimits = frozenBudget({ orderBurst: 10, renewalReserve: 0.5 });

    // exactly at the reserve, so a first issuance has nothing left to spend
    await setBudget('orders', 5);

    assert.equal(await getCertificate('flood.example.com'), false, 'nothing to serve');
    assert.equal(createCertificate.mock.callCount(), 0, 'the certificate authority was never asked');

    // held only long enough that the next handshake does not ask again at once,
    // and not counted against the domain, which did nothing wrong
    const ttl = await redisClient.ttl(blockKey('flood.example.com'));
    assert.ok(ttl > 0 && ttl <= BLOCK_NO_BUDGET_TTL, `unexpected block ttl ${ttl}`);
    assert.equal(await redisClient.exists(failureKey('flood.example.com')), 0, 'no failure was counted');
});

test('a renewal is still granted from the reserve a first issuance is refused from', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });
    restoreLimits = frozenBudget({ orderBurst: 10, renewalReserve: 0.5 });

    await seedDue('due.example.com');
    await setBudget('orders', 5);

    // the same balance that just turned a first issuance away
    assert.equal(await getCertificate('flood.example.com'), false);

    const renewed = await renew('due.example.com');
    assert.equal(renewed.status, 'valid', 'the renewal went through');
    assert.deepEqual(orderedDomains(createCertificate), ['due.example.com'], 'the only order was the renewal');
});

test('the validation budget is spent before a single DNS query is made', async t => {
    const { createCertificate, resolveCaa } = stubAcme(t, { order: issueCertificate });
    restoreLimits = frozenBudget({ validationBurst: 10, renewalReserve: 0.5 });

    await setBudget('validations', 5);

    assert.equal(await getCertificate('scanned.example.com'), false);
    assert.equal(resolveCaa.mock.callCount(), 0, 'no CAA lookup was made for a domain there was no budget to validate');
    assert.equal(createCertificate.mock.callCount(), 0);

    const ttl = await redisClient.ttl(blockKey('scanned.example.com'));
    assert.ok(ttl > 0 && ttl <= BLOCK_NO_BUDGET_TTL, `unexpected block ttl ${ttl}`);
});

test('a rate limited order stops ordering for the whole pool, not just for the domain that hit it', async t => {
    const { createCertificate } = stubAcme(t, { order: rateLimitedOrder });

    await assert.rejects(() => getCertificate('limited.example.com'), /too many new orders/);

    const ttl = await redisClient.ttl(pauseKey());
    assert.ok(ttl > 0 && ttl <= config.acme.limits.pauseBase, `unexpected pause ttl ${ttl}`);

    // a domain that has never failed anything is refused too, without spending
    // another request on discovering the same limit
    const attempts = createCertificate.mock.callCount();
    assert.equal(await getCertificate('bystander.example.com'), false);
    assert.equal(createCertificate.mock.callCount(), attempts, 'no order was placed while the pool is paused');
});

test('each consecutive rate limit doubles how long the pool waits', async t => {
    stubAcme(t, { order: rateLimitedOrder });

    await assert.rejects(() => getCertificate('first.example.com'), /too many new orders/);
    const first = await redisClient.ttl(pauseKey());

    // as if the pause had run out while the account was still over its limit
    await redisClient.del(pauseKey());
    await assert.rejects(() => getCertificate('second.example.com'), /too many new orders/);
    const second = await redisClient.ttl(pauseKey());

    assert.ok(first > 0 && first <= config.acme.limits.pauseBase, `unexpected first pause ${first}`);
    assert.ok(second > first && second <= config.acme.limits.pauseBase * 2, `unexpected second pause ${second}`);
});

test('a rate limit reported alongside a certificate that still works pauses the pool as well', async t => {
    stubAcme(t, { order: rateLimitedOrder });

    // the store swallows the error when there is something left to serve, and
    // hands the failure back on the record instead of throwing it
    await seedDue('still-good.example.com');

    const served = await renew('still-good.example.com');
    assert.equal(served.cert, 'stored-cert', 'the certificate in place is still served');
    assert.equal(served.lastError.type, RATE_LIMITED);

    assert.equal(await redisClient.exists(pauseKey()), 1, 'the pool stopped on a rate limit it never saw thrown');
});

test('a failure recorded by an earlier attempt does not pause the pool all over again', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    // A certificate that is fine, carrying a rate limit from a failure hours ago.
    // The store clears lastError only when an order succeeds, and hands the
    // record straight back on every path where it did not attempt one, so a
    // stale failure is what a healthy domain looks like for a long time after.
    await seedFresh('historic.example.com');
    await certs().setCertificateData('historic.example.com', {
        lastError: { err: '[429] too many new orders', code: null, type: RATE_LIMITED, time: new Date(Date.now() - 4 * 3600 * 1000) }
    });

    // reaches the store, which finds the certificate is not due and returns it
    const served = await renew('historic.example.com');
    assert.equal(served.cert, 'stored-cert');

    assert.equal(createCertificate.mock.callCount(), 0, 'nothing was ordered');
    assert.equal(await redisClient.exists(pauseKey()), 0, 'the pool was not paused by a rate limit that is hours old');
    assert.equal(await redisClient.exists(blockKey('historic.example.com')), 0, 'and a healthy domain was not blocked for it');
});

test('a renewal the store would not attempt backs the domain off instead of reading as a success', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    // A certificate that is due, on a domain the store has already written off:
    // its own failsafe lock from an earlier failure is still holding, so it
    // answers from the record without ordering anything and says that it did.
    await seedDue('locked.example.com');
    await seedStoreLock('locked.example.com');

    const served = await renew('locked.example.com');
    assert.equal(served.cert, 'stored-cert', 'the certificate in place is still served');
    assert.equal(createCertificate.mock.callCount(), 0, 'nothing was ordered');

    // Without this every handshake would run validateDomain and spend from both
    // budgets again, underneath a lock that is going to refuse either way.
    const ttl = await redisClient.ttl(blockKey('locked.example.com'));
    assert.ok(ttl > 0 && ttl <= BLOCK_RENEW_AFTER_FAILURE_TTL, `unexpected block ttl ${ttl}`);
});

test("the rate limit that armed the store's lock is not one the pool stops for all over again", async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    // The same refusal, on a domain whose lock was armed by a rate limit hours
    // ago. The store reports that failure, timestamp and all, because it is the
    // reason this renewal is not happening.
    await seedDue('relimited.example.com');
    await certs().setCertificateData('relimited.example.com', {
        lastError: { err: '[429] too many new orders', code: null, type: RATE_LIMITED, time: new Date(Date.now() - 4 * 3600 * 1000) }
    });
    await seedStoreLock('relimited.example.com');

    const served = await renew('relimited.example.com');
    assert.equal(served.cert, 'stored-cert');
    assert.equal(createCertificate.mock.callCount(), 0, 'nothing was ordered');

    // Pausing every domain again each time that one record is read would
    // escalate the pause until the pool never came back.
    assert.equal(await redisClient.exists(pauseKey()), 0, 'the pool was not paused by a rate limit that is hours old');

    // The domain backs off all the same: this renewal did not happen.
    assert.ok((await redisClient.ttl(blockKey('relimited.example.com'))) > 0, 'the domain was left alone for a while');
});

test('an error the certificate authority answered with blocks the domain for as long as the store does', async t => {
    stubAcme(t, { order: serverError });

    await assert.rejects(() => getCertificate('ca-error.example.com'), /having a moment/);

    // The store arms an hour long failsafe for anything the CA answered, so
    // nothing is going to be ordered inside that hour whatever this module does.
    // Matching it is what keeps validateDomain from running again underneath it.
    const ttl = await redisClient.ttl(blockKey('ca-error.example.com'));
    assert.ok(ttl > BLOCK_RENEW_AFTER_FAILURE_TTL && ttl <= BLOCK_RENEW_MAX_TTL, `unexpected block ttl ${ttl}`);
});

test('a domain that keeps failing validation is asked about less and less often', async t => {
    // a CAA record naming another certificate authority, which validateDomain
    // refuses before anything reaches the network
    const { createCertificate } = stubAcme(t, { order: issueCertificate, caa: async () => [{ issue: 'digicert.com' }] });

    const ttls = [];
    for (let attempt = 0; attempt < 3; attempt++) {
        assert.equal(await getCertificate('caa.example.com'), false);
        ttls.push(await redisClient.ttl(blockKey('caa.example.com')));
        // as if the block had run out and the handshake came back
        await redisClient.del(blockKey('caa.example.com'));
    }

    assert.equal(createCertificate.mock.callCount(), 0, 'a domain that cannot be validated never reaches the CA');
    assert.ok(ttls[0] > 0 && ttls[0] <= BLOCK_RENEW_AFTER_FAILURE_TTL, `unexpected first block ${ttls[0]}`);
    assert.ok(ttls[1] > ttls[0], `the second block (${ttls[1]}s) is longer than the first (${ttls[0]}s)`);
    assert.ok(ttls[2] > ttls[1], `the third block (${ttls[2]}s) is longer than the second (${ttls[1]}s)`);
    assert.ok(ttls[2] <= BLOCK_RENEW_MAX_TTL, `the doubling stops at the cap, got ${ttls[2]}`);
});

test('an order that goes through clears what the domain and the pool were backing off from', async t => {
    stubAcme(t, { order: issueCertificate });

    // a run of failures behind both, but neither currently held
    await redisClient.set(failureKey('recovered.example.com'), 4);
    await redisClient.set(pauseFailureKey(), 3);

    const cert = await getCertificate('recovered.example.com');
    assert.equal(cert.status, 'valid');

    assert.equal(await redisClient.exists(failureKey('recovered.example.com')), 0, 'the domain starts again from the shortest block');
    assert.equal(await redisClient.exists(pauseFailureKey()), 0, 'and the next pause from the base');
});

test('a paused pool still serves the certificates it already has', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });

    await seedDue('serving.example.com');
    await redisClient.set(pauseKey(), 1, 'EX', 900);

    // due for renewal, but it is the renewal that is paused, not the serving
    const cert = await getCertificate('serving.example.com');
    assert.equal(cert.cert, 'stored-cert');

    // the renewal getCertificate detached is the same call, awaited here so the
    // assertion below is not racing it
    assert.equal(await renew('serving.example.com'), false);
    assert.equal(createCertificate.mock.callCount(), 0, 'nothing was ordered while the pool is paused');
});

test('the store is only asked for an order once the domain has passed validation', async t => {
    const { createCertificate } = stubAcme(t, { order: issueCertificate });
    const acquire = t.mock.method(certs(), 'acquireCert');
    restoreLimits = frozenBudget({ orderBurst: 10, renewalReserve: 0.5 });

    await setBudget('orders', 5);

    assert.equal(await getCertificate('no-budget.example.com'), false);
    assert.equal(acquire.mock.callCount(), 0, 'the store never saw the domain');
    assert.equal(createCertificate.mock.callCount(), 0);
});
