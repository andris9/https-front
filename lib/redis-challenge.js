'use strict';

const { v4: uuid } = require('uuid');

// Unfinished challenges are deleted after this amount of time
const DEFAULT_KEY_TTL = 2 * 3600; // seconds

class RedisChallenge {
    static create(config = {}) {
        return new RedisChallenge(config);
    }

    constructor(config) {
        this.config = config;
        const { hashKey, redisClient, keyTtl } = this.config;

        this.uuid = uuid();
        this.hashKey = hashKey;
        this.redisClient = redisClient;
        this.keyTtl = keyTtl || DEFAULT_KEY_TTL;
    }

    hashField(domain, token) {
        return `${this.hashKey}:${domain}:${token}`;
    }

    init(/*opts*/) {
        // not much to do here
        return null;
    }

    async set(opts) {
        const { challenge } = opts;
        const { altname, keyAuthorization, token } = challenge;

        const keyName = this.hashField(altname, token);
        const res = await this.redisClient.multi().set(keyName, keyAuthorization).expire(keyName, this.keyTtl).exec();
        if (res?.[0]?.[0]) {
            throw res?.[0]?.[0];
        }
        return res?.[0]?.[1];
    }

    async get(query) {
        const { challenge } = query;
        const { identifier, token } = challenge;
        const domain = identifier.value;

        const secret = await this.redisClient.get(this.hashField(domain, token));
        return secret ? { keyAuthorization: secret } : null;
    }

    async remove(opts) {
        const { challenge } = opts;
        const { identifier, token } = challenge;
        const domain = identifier.value;

        return await this.redisClient.del(this.hashField(domain, token));
    }
}

module.exports = RedisChallenge;
