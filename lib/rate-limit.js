'use strict';

// Admission control for everything a handshake can set off that is not free:
// the DNS queries and the validation request in front of an order, and the
// order itself.
//
// The certificate authority counts orders per ACME account, not per instance,
// so a bucket that lived in a worker would be one of `proxy.workers` times the
// number of instances buckets, each convinced it had the whole budget. These
// live in Redis for the same reason the blocked marker in lib/certs.js does:
// every worker sharing a certificate pool has to be spending from one budget.

const { redisClient } = require('./db');

const { componentLogger } = require('./logger');
const logger = componentLogger('rate-limit');

// A token bucket, refilled continuously rather than in windows: a fixed window
// hands out its whole allowance at the top of the window, which is the burst
// this exists to prevent.
//
// The clock is Redis's own (TIME), not the caller's. Buckets are shared across
// instances, and a caller passing its own clock lets one skewed machine either
// write a timestamp far in the future, after which nobody refills until real
// time catches up, or refill the bucket for everyone by an hour it did not
// wait. Both are avoided by asking the one process every caller already agrees
// with.
//
// KEYS[1] bucket
// ARGV[1] capacity, ARGV[2] tokens refilled per second, ARGV[3] cost,
// ARGV[4] the level the spend may not take the bucket below
//
// Returns { granted, tokens * 1000 }: Lua returns integers to Redis, so the
// balance is scaled rather than rounded away.
const SPEND_TOKEN = `
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local floor = tonumber(ARGV[4])

local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

local tokens = capacity
local stored = redis.call('HMGET', KEYS[1], 'tokens', 'updated')
if stored[1] then
    tokens = tonumber(stored[1]) or capacity
    local updated = tonumber(stored[2]) or now
    -- A stored timestamp ahead of the server clock would refill by a negative
    -- amount. Leaving the balance alone is the safe direction: it spends less
    -- than the budget rather than more.
    if now > updated then
        tokens = math.min(capacity, tokens + (now - updated) * refill / 1000)
    end
end

local granted = 0
if tokens - cost >= floor then
    tokens = tokens - cost
    granted = 1
end

-- A spend that costs nothing is a read: what it would write back is derived
-- entirely from the stored timestamp, so writing it turns every balance check
-- into a replicated write for no change at all.
if cost > 0 then
    redis.call('HSET', KEYS[1], 'tokens', tokens, 'updated', now)
    -- Expire once the bucket would have refilled completely, since a full bucket
    -- is what a missing key already means. Keeps an abandoned pool from leaving
    -- keys behind for good.
    redis.call('PEXPIRE', KEYS[1], math.ceil(capacity * 1000 / refill) + 60000)
end

return { granted, math.floor(tokens * 1000) }
`;

redisClient.defineCommand('spendToken', { numberOfKeys: 1, lua: SPEND_TOKEN });

/**
 * Takes `cost` tokens from a bucket, unless that would take it below `floor`.
 *
 * `floor` is how one class of work is held back without starving another. A
 * renewal spends against a floor of zero because the certificate it replaces is
 * about to stop working; a first issuance spends against a floor, so a flood of
 * names nobody has a certificate for cannot take the budget the renewals of an
 * existing fleet need.
 *
 * A cost of zero reads the balance without spending it, which is how a caller
 * asks whether it is worth starting at all.
 *
 * @param {Object} opts
 * @param {String} opts.key the bucket
 * @param {Number} opts.capacity most tokens the bucket holds, which is the burst
 * @param {Number} opts.refillPerSecond tokens added per second, the sustained rate
 * @param {Number} [opts.cost] tokens this spend takes, 1 by default
 * @param {Number} [opts.floor] balance the spend may not go below, 0 by default
 * @returns {Promise<{granted: Boolean, tokens: Number}>} whether it was granted
 *   and what the balance is now
 */
const spendToken = async ({ key, capacity, refillPerSecond, cost = 1, floor = 0 }) => {
    // A bucket that cannot refill would deny everything for good once drained,
    // and a capacity below the cost can never grant anything. Neither is worth
    // failing an order over: treat an unusable configuration as no limit.
    if (!(capacity > 0) || !(refillPerSecond > 0)) {
        return { granted: true, tokens: Infinity };
    }

    try {
        const [granted, tokens] = await redisClient.spendToken(key, capacity, refillPerSecond, cost, floor);
        return { granted: !!granted, tokens: tokens / 1000 };
    } catch (err) {
        // Deny rather than pass. Everything this gates needs Redis anyway, so
        // passing would only trade a refusal here for a failure further along,
        // except that the failure further along has already spent the budget
        // this exists to protect.
        logger.error({ msg: 'Redis call failed', key, err });
        return { granted: false, tokens: 0 };
    }
};

/**
 * Sets a marker that expires by itself, doubling how long it lasts for each
 * consecutive time it is set.
 *
 * The count lives in a key of its own rather than in the marker, because it has
 * to outlast it: a count that expired with the marker would restart at the
 * shortest delay every time, and a domain that has failed nine times running
 * would be retried as eagerly as one that has failed once. `memory` is how long
 * after the longest block a run of failures is still remembered, so a domain
 * that comes good stops carrying its history.
 *
 * @param {Object} opts
 * @param {String} opts.key marker key, whose presence is what callers test
 * @param {String} opts.counterKey key the consecutive failure count lives in
 * @param {Number} opts.base seconds the first block lasts
 * @param {Number} opts.max seconds no block goes past
 * @param {Number} opts.memory seconds the count outlives the longest block by
 * @returns {Promise<{failures: Number, ttl: Number}>} the count this failure
 *   made, and how long the block it set lasts
 */
const blockWithBackoff = async ({ key, counterKey, base, max, memory }) => {
    try {
        const failures = await redisClient.incr(counterKey);
        // 2 ** a large count is Infinity rather than an overflow, which min()
        // answers with `max` like any other number too big for the cap.
        const seconds = Math.round(Math.min(base * 2 ** (failures - 1), max));

        await redisClient
            .multi()
            .expire(counterKey, max + memory)
            .set(key, failures, 'EX', seconds)
            .exec();

        return { failures, ttl: seconds };
    } catch (err) {
        logger.error({ msg: 'Redis call failed', key, counterKey, err });
        return { failures: 0, ttl: 0 };
    }
};

/**
 * Blocks for a fixed time without counting it as a failure, and without
 * shortening a block that is already in place.
 *
 * This is for being turned away by a budget rather than by anything wrong with
 * the domain. Counting it would push a domain that is only waiting its turn up
 * the same escalation as one that cannot be validated at all.
 *
 * @param {String} key marker key
 * @param {Number} ttl seconds to hold it for
 * @returns {Promise<void>}
 */
const blockBriefly = async (key, ttl) => {
    try {
        await redisClient.set(key, 0, 'EX', ttl, 'NX');
    } catch (err) {
        logger.error({ msg: 'Redis call failed', key, err });
    }
};

/**
 * Which of `keys` are set, in one round trip.
 *
 * An unreadable answer counts as blocked, whether the whole call failed or one
 * command in it did: holding an order back costs a wait, letting one through
 * unmetered costs part of an allowance there is no way to get back.
 *
 * @param {...String} keys marker keys
 * @returns {Promise<Boolean[]>} one answer per key, in the order asked
 */
const areBlocked = async (...keys) => {
    try {
        const results = await redisClient.pipeline(keys.map(key => ['exists', key])).exec();
        return results.map(([err, exists]) => (err ? true : !!exists));
    } catch (err) {
        logger.error({ msg: 'Redis call failed', keys, err });
        return keys.map(() => true);
    }
};

/**
 * True while `key` is set.
 *
 * @param {String} key marker key
 * @returns {Promise<Boolean>} whether the marker is in place
 */
const isBlocked = async key => (await areBlocked(key))[0];

/**
 * Clears a marker and the count behind it, which is what a success means.
 *
 * @param {Object} opts
 * @param {String} opts.key marker key
 * @param {String} opts.counterKey key the count lives in
 * @returns {Promise<void>}
 */
const clearBlock = async ({ key, counterKey }) => {
    try {
        await redisClient.del(key, counterKey);
    } catch (err) {
        logger.error({ msg: 'Redis call failed', key, counterKey, err });
    }
};

module.exports = { spendToken, blockWithBackoff, blockBriefly, areBlocked, isBlocked, clearBlock };
