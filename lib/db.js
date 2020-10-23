'use strict';

const config = require('wild-config');
const Redis = require('ioredis');

const redisClient = new Redis(config.redis);

module.exports = {
    redisClient
};
