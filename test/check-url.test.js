'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { closeDb, config, startRecordingServer } = require('./helpers');
const { checkUrl } = require('../lib/check-url');
const { version } = require('../package.json');

let endpoint;
const originalCheckUrl = config.checkUrl;

test.before(async () => {
    endpoint = await startRecordingServer({ body: '{"success":true}', contentType: 'application/json' });
});

test.after(async () => {
    config.checkUrl = originalCheckUrl;
    await endpoint.close();
    await closeDb();
});

test.beforeEach(() => {
    endpoint.received.length = 0;
    endpoint.respondWith({ status: 200, body: '{"success":true}' });
    config.checkUrl = {
        enabled: true,
        url: `${endpoint.url}/validate`,
        method: 'get',
        key: 'domain',
        format: 'json',
        expect: {}
    };
});

test('GET requests carry the configured path and the domain in the query string', async () => {
    assert.equal(await checkUrl('example.com'), true);

    assert.equal(endpoint.received.length, 1);
    const [req] = endpoint.received;
    assert.equal(req.method, 'GET');
    assert.equal(req.url, '/validate?domain=example.com');
});

test('GET requests keep query parameters that are already part of the URL', async () => {
    config.checkUrl.url = `${endpoint.url}/validate?source=https-front`;

    assert.equal(await checkUrl('example.com'), true);

    const url = new URL(endpoint.received[0].url, 'http://localhost');
    assert.equal(url.pathname, '/validate');
    assert.equal(url.searchParams.get('source'), 'https-front');
    assert.equal(url.searchParams.get('domain'), 'example.com');
});

test('requests identify themselves with a versioned user agent', async () => {
    await checkUrl('example.com');
    assert.equal(endpoint.received[0].headers['user-agent'], `https-front/${version}`);
});

test('POST requests send the domain as JSON by default', async () => {
    config.checkUrl.method = 'POST';

    assert.equal(await checkUrl('example.com'), true);

    const [req] = endpoint.received;
    assert.equal(req.method, 'POST');
    assert.equal(req.url, '/validate');
    assert.match(req.headers['content-type'], /^application\/json/);
    assert.deepEqual(JSON.parse(req.body), { domain: 'example.com' });
});

test('POST requests can send form encoded data', async () => {
    config.checkUrl.method = 'post';
    config.checkUrl.format = 'form';

    assert.equal(await checkUrl('example.com'), true);

    const [req] = endpoint.received;
    assert.match(req.headers['content-type'], /^application\/x-www-form-urlencoded/);
    assert.equal(new URLSearchParams(req.body).get('domain'), 'example.com');
});

test('unknown methods fall back to GET', async () => {
    config.checkUrl.method = 'options';

    assert.equal(await checkUrl('example.com'), true);
    assert.equal(endpoint.received[0].method, 'GET');
});

test('an allowed status code passes', async () => {
    config.checkUrl.expect = { status: [200, 201] };
    endpoint.respondWith({ status: 201, body: '{"success":true}' });

    assert.equal(await checkUrl('example.com'), true);
});

test('an unexpected status code throws', async () => {
    config.checkUrl.expect = { status: [201] };

    await assert.rejects(() => checkUrl('example.com'), /Invalid response status 200/);
});

test('a non 2xx response rejects before the expectations are checked', async () => {
    endpoint.respondWith({ status: 403, body: '{"success":false}' });

    await assert.rejects(() => checkUrl('example.com'), /403/);
});

test('a matching JSON key passes', async () => {
    config.checkUrl.expect = { key: 'success', value: true };

    assert.equal(await checkUrl('example.com'), true);
});

test('a nested JSON key can be addressed with dot notation', async () => {
    config.checkUrl.expect = { key: 'response.status', value: 'ok' };
    endpoint.respondWith({ body: JSON.stringify({ response: { status: 'ok' } }) });

    assert.equal(await checkUrl('example.com'), true);
});

test('a mismatching JSON value throws', async () => {
    config.checkUrl.expect = { key: 'success', value: true };
    endpoint.respondWith({ body: '{"success":false}' });

    await assert.rejects(() => checkUrl('example.com'), /Invalid value success=false/);
});

test('a missing JSON key throws', async () => {
    config.checkUrl.expect = { key: 'response.status', value: 'ok' };
    endpoint.respondWith({ body: '{"other":1}' });

    await assert.rejects(() => checkUrl('example.com'), /Invalid value response.status=undefined/);
});

test('a false expectation is enforced rather than skipped', async () => {
    config.checkUrl.expect = { key: 'blocked', value: false };

    endpoint.respondWith({ body: '{"blocked":false}' });
    assert.equal(await checkUrl('example.com'), true);

    endpoint.respondWith({ body: '{"blocked":true}' });
    await assert.rejects(() => checkUrl('example.com'), /Invalid value blocked=true/);
});

test('a text match passes when the body contains the string', async () => {
    config.checkUrl.expect = { textMatch: 'allowed' };
    endpoint.respondWith({ body: 'domain allowed', contentType: 'text/plain' });

    assert.equal(await checkUrl('example.com'), true);
});

test('a missing text match throws', async () => {
    config.checkUrl.expect = { textMatch: 'allowed' };
    endpoint.respondWith({ body: 'domain rejected', contentType: 'text/plain' });

    await assert.rejects(() => checkUrl('example.com'), /Did not find expected text "allowed"/);
});

test('a connection error is propagated', async () => {
    config.checkUrl.url = 'http://127.0.0.1:1/validate';

    await assert.rejects(() => checkUrl('example.com'), /ECONNREFUSED/);
});
