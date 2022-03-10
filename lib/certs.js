'use strict';

const crypto = require('crypto');
const ACME = require('@root/acme');
const { pem2jwk } = require('pem-jwk');
const CSR = require('@root/csr');
const { Certificate } = require('@fidm/x509');
const RedisChallenge = require('./redis-challenge');
const pkg = require('../package.json');
const { normalizeDomain } = require('./tools');
const Lock = require('ioredfour');
const util = require('util');
const { Resolver } = require('dns').promises;
const resolver = new Resolver();
const config = require('wild-config');
const Joi = require('joi');
const psl = require('psl');
const { checkUrl } = require('./check-url');

const { promisify } = require('util');
const generateKeyPair = promisify(crypto.generateKeyPair);

const pino = require('pino')();
const logger = pino.child({ app: 'https-front', component: 'certs' });

if (config?.resolver?.ns?.length) {
    resolver.setServers([].concat(config.resolver.ns || []));
}

const BLOCK_RENEW_AFTER_ERROR_TTL = 3600;
const CAA_DOMAIN = 'letsencrypt.org';

const acme = ACME.create({
    maintainerEmail: pkg.author.email,
    packageAgent: pkg.name + '/' + pkg.version,
    notify(ev, params) {
        logger.info({ msg: 'ACME Notification', ev, params });
    }
});

let getLock, releaseLock;

// First try triggers initialization, others will wait until first is finished
let acmeInitialized = false;
let acmeInitializing = false;
let acmeInitPending = [];
const ensureAcme = async options => {
    if (acmeInitialized) {
        return true;
    }
    if (acmeInitializing) {
        return new Promise((resolve, reject) => {
            acmeInitPending.push({ resolve, reject });
        });
    }

    try {
        await acme.init(options.acme.directoryUrl);
        acmeInitialized = true;

        if (acmeInitPending.length) {
            for (let entry of acmeInitPending) {
                entry.resolve(true);
            }
        }
    } catch (err) {
        if (acmeInitPending.length) {
            for (let entry of acmeInitPending) {
                entry.reject(err);
            }
        }
        throw err;
    } finally {
        acmeInitializing = false;
    }

    return true;
};

const generateKey = async (keyBits, keyExponent, opts) => {
    opts = opts || {};
    const { privateKey /*, publicKey */ } = await generateKeyPair('rsa', {
        modulusLength: keyBits || 2048, // options
        publicExponent: keyExponent || 65537,
        publicKeyEncoding: {
            type: opts.publicKeyEncoding || 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            // jwk functions fail on other encodings (eg. pkcs8)
            type: opts.privateKeyEncoding || 'pkcs1',
            format: 'pem'
        }
    });

    return privateKey;
};

const getAcmeAccount = async options => {
    await ensureAcme(options);

    const { redisClient } = options;

    const id = options.acme.key;
    const entryKey = `acme:account:${id}`;

    const acmeAccount = await redisClient.hgetall(entryKey);
    if (acmeAccount && acmeAccount.account) {
        try {
            acmeAccount.account = JSON.parse(acmeAccount.account);
        } catch (err) {
            throw new Error('Failed to retrieve ACME account');
        }
        if (acmeAccount.created) {
            acmeAccount.created = new Date(acmeAccount.created);
        }
        return acmeAccount;
    }

    // account not found, create a new one
    logger.info({ msg: 'ACME account was not found, provisioning new one', account: id, directory: options.acme.directoryUrl });
    const accountKey = await generateKey(options.keyBits);
    const jwkAccount = pem2jwk(accountKey);
    logger.info({ msg: 'Generated Acme account key', account: id });

    const accountOptions = {
        subscriberEmail: options.acme.email,
        agreeToTerms: true,
        accountKey: jwkAccount
    };

    const account = await acme.accounts.create(accountOptions);

    await redisClient.hmset(entryKey, {
        key: accountKey,
        account: JSON.stringify(account),
        created: new Date().toISOString()
    });

    logger.info({ msg: 'ACME account provisioned', account: id });
    return { key: accountKey, account };
};

let formatCertificateData = certificateData => {
    if (!certificateData) {
        return false;
    }

    ['validFrom', 'expires', 'lastCheck', 'created'].forEach(key => {
        if (certificateData[key] && typeof certificateData[key] === 'string') {
            certificateData[key] = new Date(certificateData[key]);
        }
    });

    ['dnsNames'].forEach(key => {
        if (certificateData[key] && typeof certificateData[key] === 'string') {
            try {
                certificateData[key] = JSON.parse(certificateData[key]);
            } catch (err) {
                certificateData[key] = false;
            }
        }
    });

    return certificateData;
};

const validateDomain = async domain => {
    // check domain name format
    const validation = Joi.string()
        .domain({ tlds: { allow: true } })
        .validate(domain);

    if (validation.error) {
        // invalid domain name, can not create certificate
        let err = new Error('${domain} is not a valid domain name');
        err.code = 'invalid_domain';
        throw err;
    }

    // check CAA support
    if (typeof resolver.resolveCaa === 'function') {
        // CAA support in node 15+

        let parts = domain.split('.');
        for (let i = 0; i < parts.length - 1; i++) {
            let subdomain = parts.slice(i).join('.');
            let caaRes;
            try {
                caaRes = await resolver.resolveCaa(subdomain);
            } catch (err) {
                // assume not found
            }
            if (caaRes?.length && !caaRes.some(r => (r?.issue || '').trim().toLowerCase() === CAA_DOMAIN)) {
                let err = new Error(`LE not listed in the CAA record for ${subdomain} (${domain})`);
                err.code = 'caa_mismatch';
                throw err;
            } else if (caaRes?.length) {
                logger.info({ msg: 'Found matching CAA record', subdomain, domain });
                break;
            }
        }
    }

    // resolve random domain to detect wildcard records
    if (!config?.extraChecks?.wildCardAllowed) {
        try {
            let mainDomain = psl.get(domain) || domain;
            if (mainDomain !== domain) {
                let altDomain = domain.replace(/^[^.]+\./, `${crypto.randomBytes(8).toString('hex')}.`);
                let resolved = await resolver.resolve4(altDomain);

                if (resolved && resolved.length) {
                    // wildcard DNS detected
                    let err = new Error(`Wildcard DNS detected for ${domain} of ${mainDomain} [${altDomain} resolved to ${resolved.join(', ')}]`);
                    err.code = 'wildcard_dns';
                    throw err;
                }
            }
        } catch (err) {
            if (err.code === 'wildcard_dns') {
                throw err;
            }
            // otherwise ignore
        }
    }

    if (config?.checkUrl?.enabled) {
        try {
            let validated = await checkUrl(domain);
            if (!validated) {
                throw new Error('Domain validation failed');
            }
        } catch (err) {
            logger.error({ msg: 'Domain verification failed', domain, err });
            throw err;
        }
    }

    if (!config?.precheck?.length) {
        // pass by default if precheck rules not set
        return true;
    }

    for (let check of config.precheck) {
        const { key, expected } = check;

        let queryHandler;
        switch (key.toUpperCase()) {
            case 'A':
                queryHandler = 'resolve4';
                break;
            case 'AAAA':
                queryHandler = 'resolve6';
                break;
            case 'CNAME':
                queryHandler = 'resolveCname';
                break;
            default:
                queryHandler = `resolve${key.toLowerCase().replace(/^./, c => c.toUpperCase())}`;
        }

        if (typeof resolver[queryHandler] !== 'function') {
            let err = new Error(`Unknown RR type ${key} for ${domain}`);
            err.code = 'unknown_rr_type';
            throw err;
        }

        let resolved;
        try {
            resolved = await resolver[queryHandler](domain);
        } catch (err) {
            // ignore, probably not found
        }
        if (!resolved || !resolved.length) {
            continue;
        }

        for (let row of resolved) {
            if ((row || '').toString().trim().toLowerCase() === expected.toLowerCase()) {
                return true;
            }
        }
    }

    let err = new Error(`Precheck failed for ${domain}`);
    err.code = 'precheck_failed';
    throw err;
};

const acquireCert = async opts => {
    const { redisClient, certKey, domains, options } = opts;
    let { certificateData } = opts;

    if (await redisClient.exists(`${certKey}:lock`)) {
        // nothing to do here, renewal blocked
        logger.info({ msg: 'Renewal blocked by failsafe lock', domain: domains.join(', '), certKey });

        // use default
        return certificateData;
    }

    for (let domain of domains) {
        try {
            // throws if can not validate domain
            await validateDomain(domain);
            logger.info({ msg: 'Domain validation passed', domain });
        } catch (err) {
            logger.error({ msg: 'Failed to validate domain', domain, err });
            return certificateData;
        }
    }

    // Use locking to avoid race conditions, first try gets the lock, others wait until first is finished
    if (!getLock) {
        let lock = new Lock({
            redis: redisClient,
            namespace: 'acme'
        });
        getLock = util.promisify(lock.waitAcquireLock.bind(lock));
        releaseLock = util.promisify(lock.releaseLock.bind(lock));
    }

    let lock = await getLock(certKey, 10 * 60 * 1000, 3 * 60 * 1000);
    try {
        // reload from db, maybe already renewed
        certificateData = formatCertificateData(await redisClient.hgetall(certKey));
        if (certificateData && certificateData.expires > new Date(Date.now() + 10000 + 30 * 24 * 3600 * 1000)) {
            // no need to renew
            return certificateData;
        }

        let privateKey = certificateData && certificateData.key;
        if (!privateKey) {
            // generate new key
            logger.info({ msg: 'Provision new private key', domain: domains.join(', ') });
            privateKey = await generateKey();
            await redisClient.hset(certKey, 'key', privateKey);
        }

        const jwkPrivateKey = pem2jwk(privateKey);

        let csr;

        try {
            csr = await CSR.csr({
                jwk: jwkPrivateKey,
                domains,
                encoding: 'pem'
            });
        } catch (err) {
            logger.error({ msg: 'Failed to generate CSR file', domain: domains.join(', '), err });

            if (!certificateData || certificateData.expires < new Date()) {
                // delete private key entry
                try {
                    await redisClient.del(certKey);
                } catch (err) {
                    logger.error({ msg: 'Failed to delete key from Redis', domain: domains.join(', '), certKey, err });
                }
            }

            throw err;
        }

        const acmeAccount = await getAcmeAccount(options);
        if (!acmeAccount) {
            logger.info({ msg: 'Skip certificate renwal, acme account not found', domain: domains.join(', ') });
            return false;
        }

        const jwkAccount = pem2jwk(acmeAccount.key);
        const certificateOptions = {
            account: acmeAccount.account,
            accountKey: jwkAccount,
            csr,
            domains,
            challenges: {
                'http-01': RedisChallenge.create({
                    hashKey: `acme:challenge:${options.acme.key}`,
                    redisClient
                })
            }
        };

        const aID = (acmeAccount?.account?.key?.kid || '').split('/acct/').pop();

        logger.info({ msg: 'Generate ACME cert', domain: domains.join(', '), account: aID });

        const cert = await acme.certificates.create(certificateOptions);
        if (!cert || !cert.cert) {
            logger.error({ msg: 'Failed to generate certificate for %s', domain: domains.join(', ') });
            return cert;
        }
        logger.info({ msg: 'Received certificate from ACME', domain: domains.join(', ') });

        let now = new Date();
        const parsed = Certificate.fromPEM(cert.cert);
        let result = {
            cert: cert.cert,
            chain: cert.chain,
            validFrom: new Date(parsed.validFrom).toISOString(),
            expires: new Date(parsed.validTo).toISOString(),
            dnsNames: JSON.stringify(parsed.dnsNames),
            issuer: parsed.issuer.CN,
            lastCheck: now.toISOString(),
            created: now.toISOString(),
            status: 'valid'
        };

        let updates = {};
        Object.keys(result).forEach(key => {
            updates[key] = (result[key] || '').toString();
        });

        await redisClient
            .multi()
            .hmset(certKey, updates)
            .expire(certKey, Math.round((new Date(parsed.validTo).getTime() - Date.now()) / 1000))
            .exec();

        logger.info({ msg: 'Certificate successfully generated', domain: domains.join(', '), expires: parsed.validTo });
        return formatCertificateData(await redisClient.hgetall(certKey));
    } catch (err) {
        try {
            await redisClient.multi().set(`${certKey}:lock`, 1).expire(`${certKey}:lock`, BLOCK_RENEW_AFTER_ERROR_TTL).exec();
        } catch (err) {
            logger.info({ msg: 'Redis call failed', key: `${certKey}:lock`, domain: domains.join(', '), err });
        }

        logger.info({ msg: 'Failed to generate cert', domain: domains.join(', '), err });
        if (certificateData && certificateData.cert) {
            // use existing certificate data if exists
            return certificateData;
        }

        throw err;
    } finally {
        try {
            await releaseLock(lock);
        } catch (err) {
            logger.error({ msg: 'Failed to release lock', certKey, err });
        }
    }
};

const getCertificate = async (options, domains) => {
    await ensureAcme(options);

    domains = []
        .concat(domains || [])
        .map(domain => normalizeDomain(domain))
        .filter(domain => domain);

    const { redisClient } = options;

    let domainHash = crypto.createHash('md5').update(domains.join('\x01')).digest('hex');
    let certKey = `acme:certificate:${options.acme.key}:${domainHash}`;

    let certificateData = formatCertificateData(await redisClient.hgetall(certKey));
    if (certificateData && certificateData.expires > new Date(Date.now() + 30 * 24 * 3600 * 1000)) {
        // no need to renew

        return certificateData;
    }

    if (certificateData && certificateData.expires > Date.now()) {
        // can use the stored cert and renew in background
        acquireCert({ redisClient, certKey, domains, options }).catch(err => {
            logger.error({ msg: 'Cert renewal error', domain: domains.join(', '), err });
        });

        return certificateData;
    }

    return await acquireCert({ redisClient, certKey, domains, options });
};

module.exports = {
    getCertificate
};
