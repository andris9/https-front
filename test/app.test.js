'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { closeDb, config, flushTestDb, redisClient, request, startRecordingServer, startServer } = require('./helpers');
const { app } = require('../lib/app');

const ACME_PREFIX = '/.well-known/acme-challenge/';

// The front server under test: the same wiring worker.js uses for plain HTTP.
let front;
// Stands in for the configured proxy origin.
let origin;
let originRequests = [];

const originalOrigin = config.proxy.origin;
const originalHeaders = config.proxy.headers;

const storeChallenge = (domain, token, keyAuthorization) => redisClient.set(`acme:challenge:${config.acme.key}:${domain}:${token}`, keyAuthorization);

test.before(async () => {
    await flushTestDb();

    origin = await startRecordingServer();
    originRequests = origin.received;

    front = await startServer((req, res) => {
        req.proto = 'http';
        return app(req, res);
    });

    config.proxy.origin = `${origin.url}/`;
});

test.after(async () => {
    config.proxy.origin = originalOrigin;
    config.proxy.headers = originalHeaders;
    await front.close();
    await origin.close();
    await closeDb();
});

test.beforeEach(() => {
    originRequests.length = 0;
    origin.respondWith({ body: 'origin says hello', contentType: 'text/plain' });
    config.proxy.origin = `${origin.url}/`;
    config.proxy.headers = originalHeaders;
});

test('serves a stored ACME challenge', async () => {
    await storeChallenge('acme.example.com', 'token-a', 'token-a.key-authorization');

    const res = await request(`${front.url}${ACME_PREFIX}token-a`, {
        headers: { host: 'acme.example.com' }
    });

    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /^text\/plain/);
    assert.equal(res.body, 'token-a.key-authorization');
    // the request must not reach the origin
    assert.equal(originRequests.length, 0);
});

test('challenges are scoped to the requested domain', async () => {
    await storeChallenge('scoped.example.com', 'token-b', 'token-b.key-authorization');

    const res = await request(`${front.url}${ACME_PREFIX}token-b`, {
        headers: { host: 'other.example.com' }
    });

    assert.equal(res.status, 404);
    assert.equal(res.body, 'Failed to verify authorization token');
});

test('an unknown challenge token returns 404', async () => {
    const res = await request(`${front.url}${ACME_PREFIX}nope`, {
        headers: { host: 'acme.example.com' }
    });

    assert.equal(res.status, 404);
    assert.match(res.headers['content-type'], /^text\/plain/);
    assert.equal(res.body, 'Failed to verify authorization token');
});

test('proxies everything else to the configured origin', async () => {
    const res = await request(`${front.url}/some/path?with=query`, {
        headers: { host: 'www.example.com' }
    });

    assert.equal(res.status, 200);
    assert.equal(res.body, 'origin says hello');

    assert.equal(originRequests.length, 1);
    assert.equal(originRequests[0].method, 'GET');
    assert.equal(originRequests[0].url, '/some/path?with=query');
    // the original Host header is preserved, changeOrigin is off
    assert.equal(originRequests[0].headers.host, 'www.example.com');
});

test('forwards request bodies and methods', async () => {
    const res = await request(`${front.url}/submit`, {
        method: 'POST',
        headers: { host: 'www.example.com', 'content-type': 'application/json' },
        body: '{"hello":"world"}'
    });

    assert.equal(res.status, 200);
    assert.equal(originRequests[0].method, 'POST');
    assert.equal(originRequests[0].body, '{"hello":"world"}');
});

test('tells the origin about the protocol and the connecting IP', async () => {
    await request(`${front.url}/`, { headers: { host: 'www.example.com' } });

    const [proxied] = originRequests;
    assert.equal(proxied.headers['x-forwarded-proto'], 'http');
    assert.equal(proxied.headers['x-connecting-ip'], '127.0.0.1');
    assert.equal(proxied.headers['x-forwarded-for'], '127.0.0.1');
    assert.equal(proxied.headers['x-forwarded-host'], 'www.example.com');
});

test('adds the configured response headers', async () => {
    config.proxy.headers = [
        { key: 'server', value: 'https-front/test' },
        { key: 'x-extra', value: 'yes' },
        // incomplete entries are ignored
        { key: 'x-no-value' },
        { value: 'x-no-key' },
        {}
    ];

    const res = await request(`${front.url}/`, { headers: { host: 'www.example.com' } });

    assert.equal(res.status, 200);
    assert.equal(res.headers.server, 'https-front/test');
    assert.equal(res.headers['x-extra'], 'yes');
    assert.equal(res.headers['x-no-value'], undefined);
});

test('renders the 502 page when the origin is unreachable', async () => {
    // nothing can listen on port 1 without root, so the connection is refused
    config.proxy.origin = 'http://127.0.0.1:1/';

    const res = await request(`${front.url}/`, { headers: { host: 'www.example.com' } });

    assert.equal(res.status, 502);
    assert.match(res.headers['content-type'], /^text\/html/);
    assert.match(res.body, /Something went wrong/);
});

test('survives a request without a Host header', async () => {
    const res = await request(`${front.url}/`, { headers: { host: '' } });

    assert.equal(res.status, 200);
    assert.equal(originRequests.length, 1);
});
