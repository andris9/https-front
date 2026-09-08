'use strict';

// Reads the certificate store that releases up to 1.4.x wrote, back when this
// proxy spoke ACME through @root/acme and kept its own Redis layout: the account
// in a hash at `acme:account:<key>`, and one hash per certificate at
// `acme:certificate:<key>:<md5 of the domain list>`.
//
// @postalsys/certs stores both differently, so an instance upgraded in place
// would otherwise register a new ACME account and re-order every certificate it
// already holds. Nothing here is a migration step to run: the account is
// imported before the first order and a certificate the first time its domain is
// looked up, so only the domains that still get traffic are carried over. The
// old entries are left alone, and expire on their own.
//
// This module can be deleted once every instance sharing a certificate pool has
// been running a release that reads the new layout.

const crypto = require('crypto');
const config = require('@zone-eu/wild-config');
const { normalizeDomain, parseCertificate } = require('@postalsys/certs/lib/tools');

const { redisClient } = require('./db');

const { componentLogger } = require('./logger');
const logger = componentLogger('legacy-certs');

// The Redis key the old code stored the ACME account under.
const accountKey = () => `acme:account:${config.acme.key}`;

// Where the store keeps the account the import writes.
const accountSettingKey = certs => `account:${certs.acmeOptions.environment}`;

// The Redis key the old code stored the certificate for these domains under. A
// certificate was ordered for one domain at a time, so hashing a single name is
// what every stored key was built from.
const certificateKey = domain => `acme:certificate:${config.acme.key}:${crypto.createHash('md5').update(domain).digest('hex')}`;

/**
 * Carries the ACME account of an earlier release over to the new store, so that
 * the certificates it already ordered keep counting against the same account.
 *
 * @param {Object} certs @postalsys/certs instance
 * @returns {Boolean} true when an account was imported
 */
const importAccount = async certs => {
    const settingKey = accountSettingKey(certs);

    try {
        if (await certs.settings.has(settingKey)) {
            // an account is already in place, nothing to carry over
            return false;
        }

        const stored = await redisClient.hgetall(accountKey());
        if (!stored || !stored.key || !stored.account) {
            return false;
        }

        // An account whose stored copy has no key ID is carried over all the
        // same: the store re-registers the same key, and the CA answers a
        // newAccount for a key it already knows with the existing registration.
        await certs.settings.set(settingKey, {
            privateKey: await certs.encryptFn(stored.key),
            account: JSON.parse(stored.account)
        });

        logger.info({ msg: 'Imported the ACME account of an earlier release', key: accountKey() });
        return true;
    } catch (err) {
        // A new account is registered instead, which costs an ACME registration
        // but leaves the instance able to order certificates.
        logger.error({ msg: 'Failed to import the ACME account of an earlier release', key: accountKey(), err });
        return false;
    }
};

/**
 * Carries the certificate an earlier release stored for `domain` over to the new
 * store, so that an upgraded instance keeps serving it instead of ordering a
 * replacement on the first handshake.
 *
 * @param {Object} certs @postalsys/certs instance
 * @param {String} domain domain name in its A-label form
 * @returns {Object|false} the imported certificate data, or false when there was
 *   nothing usable to import
 */
const importCertificate = async (certs, domain) => {
    const key = certificateKey(domain);

    try {
        const stored = await redisClient.hgetall(key);
        if (!stored || !stored.cert || !stored.key) {
            return false;
        }

        const parsed = parseCertificate(stored.cert);
        if (parsed.validTo.getTime() <= Date.now()) {
            // expired, so it would be replaced the moment it was imported
            logger.info({ msg: 'Skipped an expired certificate of an earlier release', domain, key });
            return false;
        }

        // The store holds domains in their Unicode spelling, including as keys.
        const name = normalizeDomain(domain);

        if (!parsed.altNames.includes(name)) {
            // The old code filed a certificate under the domain it was ordered
            // for, so this does not happen on a record it wrote. Filing one that
            // does not cover the domain would serve the wrong certificate for it.
            logger.error({ msg: 'Certificate of an earlier release does not cover the domain', domain, key, altNames: parsed.altNames });
            return false;
        }
        const record = Object.assign({ domain: name }, parsed, {
            cert: stored.cert,
            ca: [].concat(stored.chain || []).filter(entry => entry),
            privateKey: stored.key,
            lastCheck: new Date(),
            lastError: null,
            // nothing was ever fetched for a certificate this old
            renewalInfo: null,
            status: 'valid'
        });

        await certs.setCertificateData(name, record);

        logger.info({ msg: 'Imported a certificate of an earlier release', domain, key, expires: parsed.validTo });

        // what was just written, rather than a second read of it
        return record;
    } catch (err) {
        // Nothing was imported, so the domain is ordered from scratch.
        logger.error({ msg: 'Failed to import a certificate of an earlier release', domain, key, err });
        return false;
    }
};

module.exports = {
    importAccount,
    importCertificate,

    // Internals exposed for the test suite only, not part of the public API.
    testables: {
        accountKey,
        accountSettingKey,
        certificateKey
    }
};
