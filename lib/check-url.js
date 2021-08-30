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

                console.log('POST', config.checkUrl.url, data);
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
            console.log('GET', url.origin);
            res = await axios.get(url.origin, {
                headers: {
                    'User-Agent': `https-front/${packageData.version}`
                }
            });
        }
    }

    console.log(require('util').inspect(res, false, 22));

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

    return true;
}

module.exports.checkUrl = checkUrl;