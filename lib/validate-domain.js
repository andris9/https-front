'use strict';

const config = require('wild-config');
const axios = require('axios');
const packageData = require('../package.json');

async function validateDomain(domain) {
    let res;

    switch ((config.validate.method || '').toLowerCase()) {
        case 'post':
            {
                let data;

                if (config.validate.format === 'form') {
                    //application/x-www-form-urlencoded
                    data = new URLSearchParams();
                    data.append(config.validate.key, domain);
                } else {
                    // json
                    data = { [config.validate.key]: domain };
                }

                res = await axios.post(config.validate.url, data, {
                    headers: {
                        'User-Agent': `https-front/${packageData.version}`
                    }
                });
            }
            break;
        case 'get':
        default: {
            let url = new URL(config.validate.url);
            url.searchParams.set(config.validate.key, domain);
            res = await axios.get(url, {
                headers: {
                    'User-Agent': `https-front/${packageData.version}`
                }
            });
        }
    }

    let expect = config.validate.expect || {};

    if (expect.status && ![].concat(expect.status).includes(res.status)) {
        // status code check failed
        let err = new Error(`Invalid response status ${res.status}`);
        err.statusCode = res.status;
        throw err;
    }

    if (expect.key && expect.value) {
        let keyPath = expect.key.split('.');
        let value;
        if (res.data && typeof res.data === 'object') {
            value = res.data;
            while (keyPath.length && value) {
                let key = keyPath.shift();
                value = value[key];
            }
        }
        if (expect.value !== value) {
            let err = new Error(`Invalid value ${expect.key}=${value} (expected ${expect.value})`);
            err.statusCode = res.status;
            throw err;
        }
    }

    return true;
}

module.exports.validateDomain = validateDomain;
