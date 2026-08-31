'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { redisClient, flushTestDb, closeDb } = require('./helpers');
const RedisChallenge = require('../lib/redis-challenge');

const HASH_KEY = 'acme:challenge:unit';

const newChallenge = opts => RedisChallenge.create(Object.assign({ hashKey: HASH_KEY, redisClient }, opts));

test.before(async () => {
    await flushTestDb();
});

test.after(async () => {
    await closeDb();
});

test('create() returns a configured instance', () => {
    const challenge = newChallenge();
    assert.ok(challenge instanceof RedisChallenge);
    assert.equal(challenge.hashKey, HASH_KEY);
    assert.equal(challenge.redisClient, redisClient);
    // 2 hours by default
    assert.equal(challenge.keyTtl, 2 * 3600);
    assert.match(challenge.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-/);
});

test('create() honours a custom key TTL', () => {
    assert.equal(newChallenge({ keyTtl: 30 }).keyTtl, 30);
});

test('every instance gets its own uuid', () => {
    assert.notEqual(newChallenge().uuid, newChallenge().uuid);
});

test('hashField() namespaces domain and token', () => {
    assert.equal(newChallenge().hashField('example.com', 'tok'), `${HASH_KEY}:example.com:tok`);
});

test('init() is a no-op', () => {
    assert.equal(newChallenge().init({}), null);
});

test('set() stores the key authorization with a TTL', async () => {
    const challenge = newChallenge();
    await challenge.set({
        challenge: { altname: 'set.example.com', token: 'token-1', keyAuthorization: 'auth-1' }
    });

    const key = challenge.hashField('set.example.com', 'token-1');
    assert.equal(await redisClient.get(key), 'auth-1');

    const ttl = await redisClient.ttl(key);
    assert.ok(ttl > 2 * 3600 - 10 && ttl <= 2 * 3600, `unexpected ttl ${ttl}`);
});

test('set() applies the configured key TTL', async () => {
    const challenge = newChallenge({ keyTtl: 60 });
    await challenge.set({
        challenge: { altname: 'ttl.example.com', token: 'token-2', keyAuthorization: 'auth-2' }
    });

    const ttl = await redisClient.ttl(challenge.hashField('ttl.example.com', 'token-2'));
    assert.ok(ttl > 50 && ttl <= 60, `unexpected ttl ${ttl}`);
});

test('get() returns the stored authorization', async () => {
    const challenge = newChallenge();
    await challenge.set({
        challenge: { altname: 'get.example.com', token: 'token-3', keyAuthorization: 'auth-3' }
    });

    const stored = await challenge.get({
        challenge: { identifier: { value: 'get.example.com' }, token: 'token-3' }
    });
    assert.deepEqual(stored, { keyAuthorization: 'auth-3' });
});

test('get() returns null for an unknown challenge', async () => {
    const challenge = newChallenge();

    assert.equal(
        await challenge.get({
            challenge: { identifier: { value: 'missing.example.com' }, token: 'nope' }
        }),
        null
    );

    // right domain, wrong token
    await challenge.set({
        challenge: { altname: 'partial.example.com', token: 'token-4', keyAuthorization: 'auth-4' }
    });
    assert.equal(
        await challenge.get({
            challenge: { identifier: { value: 'partial.example.com' }, token: 'other-token' }
        }),
        null
    );
});

test('challenges are scoped by hash key', async () => {
    const first = newChallenge();
    const second = newChallenge({ hashKey: 'acme:challenge:other' });

    await first.set({
        challenge: { altname: 'scope.example.com', token: 'token-5', keyAuthorization: 'auth-5' }
    });

    assert.equal(
        await second.get({
            challenge: { identifier: { value: 'scope.example.com' }, token: 'token-5' }
        }),
        null
    );
});

test('remove() expires the challenge shortly after use', async () => {
    const challenge = newChallenge();
    await challenge.set({
        challenge: { altname: 'remove.example.com', token: 'token-6', keyAuthorization: 'auth-6' }
    });

    const removed = await challenge.remove({
        challenge: { identifier: { value: 'remove.example.com' }, token: 'token-6' }
    });
    assert.equal(removed, 1);

    const ttl = await redisClient.ttl(challenge.hashField('remove.example.com', 'token-6'));
    assert.ok(ttl > 0 && ttl <= 10, `unexpected ttl ${ttl}`);
});

test('remove() reports a miss for an unknown challenge', async () => {
    const removed = await newChallenge().remove({
        challenge: { identifier: { value: 'unknown.example.com' }, token: 'token-7' }
    });
    assert.equal(removed, 0);
});
