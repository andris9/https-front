'use strict';

// Renewals driven by a clock rather than by traffic.
//
// Every certificate this proxy holds was ordered because a handshake asked for
// one, and renewals used to be ordered the same way. That ties the rate
// certificates are renewed at to the shape of the traffic: they arrive in the
// peaks, which is when there is least room for them, and a domain quiet enough
// not to be asked for between its renewal falling due and its certificate
// expiring is renewed by the first visitor after it has already stopped
// working, from inside that visitor's TLS handshake.
//
// A pass walks the pool instead, a slice of it per tick, and orders what is due
// through the same budget in lib/certs.js that a handshake spends from. One
// worker runs it at a time, elected through Redis, because the work is per
// certificate pool rather than per process.

const crypto = require('crypto');
const config = require('@zone-eu/wild-config');
const { isRenewalDue } = require('@postalsys/certs');

const { redisClient } = require('./db');
const { listDomains, storedCertificate, renew, orderBudget, ordersPaused, poolKey } = require('./certs');

const { componentLogger } = require('./logger');
const logger = componentLogger('renewal');

// Documented once in config/default.toml, which is always merged underneath
// whatever else is configured. These are the fallback for an installation
// pointed at a configuration directory of its own, where that file is not there
// to be merged from.
const DEFAULTS = {
    interval: 60,
    batchSize: 500,
    concurrency: 4
};

// Identifies this worker to the others sharing the pool. Random rather than the
// pid, which repeats across the machines an instance is one of.
const INSTANCE_ID = crypto.randomBytes(8).toString('hex');

const leaseKey = () => poolKey('renewal:leader');

const settings = () => {
    const renewal = config.renewal || {};
    return {
        enabled: renewal.enabled !== false,
        interval: Number(renewal.interval) > 0 ? Number(renewal.interval) : DEFAULTS.interval,
        batchSize: Number(renewal.batchSize) > 0 ? Number(renewal.batchSize) : DEFAULTS.batchSize,
        concurrency: Number(renewal.concurrency) > 0 ? Number(renewal.concurrency) : DEFAULTS.concurrency
    };
};

// The pool being walked, and how far through it this worker has read. Kept
// across ticks so that one tick is one slice: reading the whole domain list is
// the one call in here worth not repeating, and a pass over a large pool is
// meant to take hours.
let queue = [];
let cursor = 0;

let timer = null;
let ticking = false;

// Drops the pool this worker was walking. The next pass reads it again from the
// beginning, which is what a worker that has not been the leader for a while
// should be doing anyway.
const forget = () => {
    queue = [];
    cursor = 0;
};

/**
 * Takes the lease, or extends one this worker already holds.
 *
 * Two leaders would mean two scans rather than two orders: ordering goes through
 * the same per domain lock inside the store and the same budget either way, so
 * losing the lease to a slow tick costs Redis reads and nothing else.
 *
 * @returns {Promise<Boolean>} whether this worker may run the pass
 */
const takeLease = async () => {
    // Long enough that a leader busy with a slice is not replaced under it,
    // short enough that a worker that died is replaced within a few ticks.
    const ttl = settings().interval * 3;
    const key = leaseKey();

    if (await redisClient.set(key, INSTANCE_ID, 'EX', ttl, 'NX')) {
        return true;
    }

    if ((await redisClient.get(key)) !== INSTANCE_ID) {
        return false;
    }

    await redisClient.expire(key, ttl);
    return true;
};

/**
 * The next slice of the pool, starting a new pass once the last one ran out.
 *
 * @param {Number} batchSize domains to take
 * @returns {Promise<String[]>} the domains in this slice
 */
const nextSlice = async batchSize => {
    if (cursor >= queue.length) {
        queue = await listDomains();
        cursor = 0;
        logger.info({ msg: 'Starting a renewal pass', domains: queue.length });
    }

    const slice = queue.slice(cursor, cursor + batchSize);
    cursor += slice.length;
    return slice;
};

/**
 * Runs `handle` over `items`, `concurrency` of them at a time.
 *
 * Workers pull from one shared queue rather than taking a share each, so a slow
 * domain holds up nothing but itself. A `handle` that returns false stops its
 * worker and puts the item it was given back, which is how a caller that has run
 * out of something says so.
 *
 * @param {Array} items work to get through
 * @param {Number} concurrency how many at a time
 * @param {Function} handle called with one item, awaited
 * @returns {Promise<Array>} whatever was left unhandled
 */
const eachLimited = async (items, concurrency, handle) => {
    const pending = items.slice();

    const worker = async () => {
        for (;;) {
            const item = pending.shift();
            if (item === undefined) {
                return;
            }

            if ((await handle(item)) === false) {
                pending.unshift(item);
                return;
            }
        }
    };

    await Promise.all(Array.from({ length: Math.min(Math.max(concurrency, 1), pending.length) }, worker));
    return pending;
};

/**
 * The domains in `slice` whose certificates are due, soonest to expire first.
 *
 * Ordering them matters once the budget is tight: a pass that runs out partway
 * through should run out on the certificates with the most life left rather than
 * on the ones about to expire.
 *
 * @param {String[]} slice domains to look at
 * @param {Number} [concurrency] records read at a time
 * @returns {Promise<String[]>} the due ones, in the order to renew them
 */
const collectDue = async (slice, concurrency = 1) => {
    const due = [];

    // Read a few at a time rather than one after another: a slice is hundreds of
    // records, each of them a round trip this would otherwise spend waiting on
    // before starting the next.
    await eachLimited(slice, concurrency, async domain => {
        let certificateData;
        try {
            certificateData = await storedCertificate(domain);
        } catch (err) {
            logger.error({ msg: 'Failed to read a certificate record', domain, err });
            return;
        }

        // A record with no certificate is an order that never finished. Leaving
        // those to the handshake that wanted them keeps a pass from ordering for
        // domains nothing is asking for any more.
        if (certificateData && certificateData.cert && isRenewalDue(certificateData)) {
            due.push({ domain, validTo: new Date(certificateData.validTo).getTime() });
        }
    });

    return due.sort((a, b) => a.validTo - b.validTo).map(entry => entry.domain);
};

/**
 * Renews `domains` in order, a few at a time, and stops as soon as the order
 * budget is gone.
 *
 * The budget is checked before each order rather than trusted from the start of
 * the slice: handshakes are spending from the same bucket throughout.
 *
 * @param {String[]} domains the due domains, most urgent first
 * @param {Number} concurrency orders to run at once
 * @returns {Promise<Number>} how many renewals were started
 */
const renewAll = async (domains, concurrency) => {
    let started = 0;
    let exhausted = false;

    const remaining = await eachLimited(domains, concurrency, async domain => {
        // Every worker asks for itself rather than watching a shared flag. The
        // flag would save the others a Redis read each once the first one has
        // given up, which is a handful of reads at the end of a pass, and it
        // would answer from before whatever the handshakes spending from the
        // same bucket have done since.
        if ((await orderBudget()) < 1) {
            exhausted = true;
            return false;
        }

        started++;
        try {
            await renew(domain);
        } catch (err) {
            // acquireCert() has already recorded the failure and blocked the
            // domain; a pass carries on with the rest of the slice.
            logger.error({ msg: 'Renewal failed', domain, err });
        }
    });

    if (exhausted) {
        logger.info({ msg: 'Renewal pass ran out of order budget', started, remaining: remaining.length });
    }

    return started;
};

/**
 * One slice: read it, work out what is due and renew as much of it as the budget
 * allows.
 *
 * @returns {Promise<void>}
 */
const runPass = async () => {
    const { batchSize, concurrency } = settings();

    if (await ordersPaused()) {
        logger.info({ msg: 'Renewal pass skipped, orders are paused' });
        return;
    }

    if ((await orderBudget()) < 1) {
        logger.info({ msg: 'Renewal pass skipped, no order budget' });
        return;
    }

    const slice = await nextSlice(batchSize);
    if (!slice.length) {
        return;
    }

    const due = await collectDue(slice, concurrency);
    if (!due.length) {
        return;
    }

    const started = await renewAll(due, concurrency);
    logger.info({ msg: 'Renewal pass finished', scanned: slice.length, due: due.length, started });
};

/**
 * One tick. Never runs on top of itself: a slice that takes longer than the
 * interval skips the ticks it overran rather than stacking passes up behind it.
 *
 * @returns {Promise<void>}
 */
const tick = async () => {
    if (ticking) {
        return;
    }
    ticking = true;

    try {
        if (await takeLease()) {
            await runPass();
        } else {
            // Another worker has the pass. At a hundred thousand domains the
            // slice queue is megabytes, and holding it here would keep it for as
            // long as this worker lives without ever reading from it again.
            forget();
        }
    } catch (err) {
        logger.error({ msg: 'Renewal pass failed', err });
    } finally {
        ticking = false;
    }
};

/**
 * Starts the pass timer, unless it is already running or renewals are switched
 * off.
 *
 * @returns {Boolean} whether a timer was started
 */
const start = () => {
    const { enabled, interval } = settings();

    if (!enabled || timer) {
        return false;
    }

    // Unref'd: the listening sockets are what should keep a worker alive, and a
    // worker that has lost them should not be held up by this.
    timer = setInterval(tick, interval * 1000).unref();
    logger.info({ msg: 'Renewal sweeper started', interval });
    return true;
};

/**
 * Stops the pass timer. The lease is left to expire, so that a worker shutting
 * down does not hand the pool to another one mid-slice.
 *
 * @returns {void}
 */
const stop = () => {
    if (timer) {
        clearInterval(timer);
        timer = null;
    }
    forget();
};

module.exports = {
    start,
    stop,

    // Internals exposed for the test suite only, not part of the public API.
    testables: {
        INSTANCE_ID,
        collectDue,
        leaseKey,
        nextSlice,
        runPass,
        settings,
        takeLease,
        tick,
        reset: forget
    }
};
