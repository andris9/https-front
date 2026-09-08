'use strict';

// Covers lib/rate-limit.js on its own: the token bucket every order and every
// domain validation is admitted through, and the markers that hold a domain, or
// the whole pool, back after something went wrong. Redis is real here; nothing
// above this module is involved.

const test = require('node:test');
const assert = require('node:assert/strict');

const { closeDb, flushTestDb, redisClient, seedBucket } = require('./helpers');
const { spendToken, blockWithBackoff, blockBriefly, areBlocked, isBlocked, clearBlock } = require('../lib/rate-limit');

const KEY = 'test:bucket';
const MARKER = 'test:blocked';
const COUNTER = 'test:failures';

// A bucket that refills so slowly that nothing refills during a test, which is
// how the spends below are counted rather than raced.
const frozen = { key: KEY, capacity: 3, refillPerSecond: 0.0000001 };

test.before(async () => {
    await flushTestDb();
});

test.after(async () => {
    await closeDb();
});

test.beforeEach(async () => {
    await flushTestDb();
});

test('a bucket hands out its capacity and then stops', async () => {
    for (let i = 0; i < 3; i++) {
        assert.equal((await spendToken(frozen)).granted, true, `spend ${i + 1} of the capacity`);
    }

    const spent = await spendToken(frozen);
    assert.equal(spent.granted, false, 'the bucket is empty');
    assert.ok(spent.tokens < 1, `unexpected balance ${spent.tokens}`);
});

test('tokens come back at the refill rate', async () => {
    // empty a second ago, refilling ten a second, so it is full again
    await seedBucket(KEY, 0, 1000);

    const spent = await spendToken({ key: KEY, capacity: 10, refillPerSecond: 10 });

    assert.equal(spent.granted, true);
    assert.equal(spent.tokens, 9, 'refilled to capacity, then spent one');
});

test('a floor holds one class of spend back without stopping the other', async () => {
    await seedBucket(KEY, 5);

    const held = await spendToken({ key: KEY, capacity: 10, refillPerSecond: 0.0000001, floor: 5 });
    assert.equal(held.granted, false, 'a spend that would go below the floor is refused');
    assert.equal(held.tokens, 5, 'and takes nothing');

    const allowed = await spendToken({ key: KEY, capacity: 10, refillPerSecond: 0.0000001, floor: 0 });
    assert.equal(allowed.granted, true, 'the same balance is still there for a spend with no floor');
    assert.equal(allowed.tokens, 4);
});

test('a spend that costs nothing reads the balance without taking any', async () => {
    await seedBucket(KEY, 7);

    const peeked = await spendToken({ key: KEY, capacity: 10, refillPerSecond: 0.0000001, cost: 0 });
    assert.equal(peeked.granted, true);
    assert.equal(peeked.tokens, 7);

    // reading it did not spend it
    assert.equal((await spendToken({ key: KEY, capacity: 10, refillPerSecond: 0.0000001, cost: 0 })).tokens, 7);
});

test('a bucket that could never refill is treated as no limit at all', async () => {
    for (const unusable of [{ capacity: 10, refillPerSecond: 0 }, { capacity: 0, refillPerSecond: 10 }, {}]) {
        const spent = await spendToken(Object.assign({ key: KEY }, unusable));
        assert.equal(spent.granted, true, `${JSON.stringify(unusable)} is not a limit`);
        assert.equal(spent.tokens, Infinity);
    }

    assert.equal(await redisClient.exists(KEY), 0, 'and nothing was written for it');
});

test('a Redis failure denies the spend rather than letting it through unmetered', async t => {
    t.mock.method(redisClient, 'spendToken', async () => {
        throw new Error('redis is unhappy');
    });

    assert.deepEqual(await spendToken(frozen), { granted: false, tokens: 0 });
});

test('a block doubles for each consecutive failure and stops at the cap', async () => {
    const block = () => blockWithBackoff({ key: MARKER, counterKey: COUNTER, base: 10, max: 40, memory: 5 });

    assert.deepEqual(await block(), { failures: 1, ttl: 10 });
    assert.deepEqual(await block(), { failures: 2, ttl: 20 });
    assert.deepEqual(await block(), { failures: 3, ttl: 40 });
    assert.deepEqual(await block(), { failures: 4, ttl: 40 }, 'the doubling stops at the cap');

    const ttl = await redisClient.ttl(MARKER);
    assert.ok(ttl > 0 && ttl <= 40, `unexpected marker ttl ${ttl}`);
});

test('a block that starts at the cap stays there', async () => {
    // what lib/certs.js does for an error the certificate authority answered,
    // where the store has already written off the next hour
    const block = () => blockWithBackoff({ key: MARKER, counterKey: COUNTER, base: 3600, max: 3600, memory: 5 });

    assert.deepEqual(await block(), { failures: 1, ttl: 3600 });
    assert.deepEqual(await block(), { failures: 2, ttl: 3600 });

    const ttl = await redisClient.ttl(MARKER);
    assert.ok(ttl > 3500 && ttl <= 3600, `unexpected marker ttl ${ttl}`);
});

test('the failure count outlives the block it set, so the next one escalates', async () => {
    await blockWithBackoff({ key: MARKER, counterKey: COUNTER, base: 10, max: 40, memory: 60 });

    const markerTtl = await redisClient.ttl(MARKER);
    const counterTtl = await redisClient.ttl(COUNTER);

    assert.ok(counterTtl > markerTtl, `the count (${counterTtl}s) outlives the block (${markerTtl}s)`);
    assert.ok(counterTtl > 40 && counterTtl <= 100, `unexpected counter ttl ${counterTtl}`);
});

test('a brief block is not counted as a failure and never shortens one already in place', async () => {
    await blockBriefly(MARKER, 60);

    const ttl = await redisClient.ttl(MARKER);
    assert.ok(ttl > 0 && ttl <= 60, `unexpected marker ttl ${ttl}`);
    assert.equal(await redisClient.exists(COUNTER), 0, 'nothing was counted against the domain');

    // a longer block is left alone rather than cut back to the brief one
    await redisClient.del(MARKER);
    await blockWithBackoff({ key: MARKER, counterKey: COUNTER, base: 3600, max: 3600, memory: 60 });
    await blockBriefly(MARKER, 60);

    assert.ok((await redisClient.ttl(MARKER)) > 60, 'the longer block survived');
});

test('several markers are read in one round trip', async () => {
    await blockBriefly(MARKER, 60);

    assert.deepEqual(await areBlocked(MARKER, 'test:absent'), [true, false], 'answered in the order asked');
    assert.equal(await isBlocked(MARKER), true);
    assert.equal(await isBlocked('test:absent'), false);
});

test('a marker that cannot be read counts as blocked', async t => {
    // the whole call failing
    t.mock.method(redisClient, 'pipeline', () => {
        throw new Error('redis is unhappy');
    });
    assert.deepEqual(await areBlocked(MARKER, 'test:absent'), [true, true], 'an unreadable answer holds the order back');

    // and one command inside it failing while the rest succeed
    redisClient.pipeline.mock.restore();
    t.mock.method(redisClient, 'pipeline', () => ({
        exec: async () => [
            [new Error('WRONGTYPE'), null],
            [null, 0]
        ]
    }));
    assert.deepEqual(await areBlocked(MARKER, 'test:absent'), [true, false], 'only the command that failed counts as blocked');
});

test('clearing a block removes the count with it, or the count on its own', async () => {
    await blockWithBackoff({ key: MARKER, counterKey: COUNTER, base: 10, max: 40, memory: 60 });

    await clearBlock({ counterKey: COUNTER });
    assert.equal(await redisClient.exists(MARKER), 1, 'the block itself is left to expire');
    assert.equal(await redisClient.exists(COUNTER), 0, 'the escalation starts again from the base');

    await clearBlock({ key: MARKER, counterKey: COUNTER });
    assert.equal(await redisClient.exists(MARKER), 0);
});

test('a Redis failure while blocking is reported rather than thrown', async t => {
    t.mock.method(redisClient, 'incr', async () => {
        throw new Error('redis is unhappy');
    });
    t.mock.method(redisClient, 'set', async () => {
        throw new Error('redis is unhappy');
    });
    t.mock.method(redisClient, 'del', async () => {
        throw new Error('redis is unhappy');
    });

    assert.deepEqual(await blockWithBackoff({ key: MARKER, counterKey: COUNTER, base: 10, max: 40, memory: 5 }), { failures: 0, ttl: 0 });
    await blockBriefly(MARKER, 60);
    await clearBlock({ key: MARKER, counterKey: COUNTER });
});
