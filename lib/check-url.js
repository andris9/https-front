'use strict';

const config = require('wild-config');
const axios = require('axios');
const packageData = require('../package.json');

async function checkUrl(domain) {
    let res;

    switch ((config.checkUrl.method || '').toLowerCase()) {
        case 'post':
            {
                let data;

                if (config.checkUrl.format === 'form') {
                    //application/x-www-form-urlencoded
                    data = new URLSearchParams();
                    data.append(config.checkUrl.key, domain);
                } else {
                    // json
                    data = { [config.checkUrl.key]: domain };
                }

                res = await axios.post(config.checkUrl.url, data, {
                    headers: {
                        'User-Agent': `https-front/${packageData.version}`
                    }
                });
            }
            break;
        case 'get':
        default: {
            let url = new URL(config.checkUrl.url);
            url.searchParams.set(config.checkUrl.key, domain);
            res = await axios.get(url.origin, {
                headers: {
                    'User-Agent': `https-front/${packageData.version}`
                }
            });
        }
    }

    let expect = config.checkUrl.expect || {};

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

    if (expect.textMatch) {
        let data = res.data && Buffer.isBuffer(res.data) ? res.data.toString() : res.data;
        if (typeof data !== 'string' || data.indexOf(expect.textMatch) < 0) {
            let err = new Error(`Did not find expected text "${expect.textMatch}"`);
            err.statusCode = res.status;
            throw err;
        }
    }

    return true;
}

module.exports.checkUrl = checkUrl;
