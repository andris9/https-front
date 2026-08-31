'use strict';

// Regression coverage for the proxying layer. These cases pin down the
// behaviour that has to survive a change of proxy library: status codes,
// headers, bodies, streaming and the failure modes of a misbehaving origin.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { closeDb, config, delay, flushTestDb, request, startServer } = require('./helpers');
const { app } = require('../lib/app');

let front;
let origin;
let handler;

const originalOrigin = config.proxy.origin;
const originalHeaders = config.proxy.headers;

test.before(async () => {
    await flushTestDb();

    origin = await startServer((req, res) => handler(req, res));
    front = await startServer((req, res) => {
        req.proto = 'https';
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
    config.proxy.origin = `${origin.url}/`;
    config.proxy.headers = originalHeaders;
    handler = (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
    };
});

const get = (path = '/', opts = {}) =>
    request(`${front.url}${path}`, Object.assign({}, opts, { headers: Object.assign({ host: 'proxy.example.com' }, opts.headers) }));

// Runs `scenario` while watching for an uncaught exception, then checks that the
// proxy still serves the next request.
const assertSurvives = async scenario => {
    const uncaught = [];
    const collect = err => uncaught.push(err);
    process.on('uncaughtException', collect);

    try {
        await scenario();
        // let any deferred error handler run
        await delay(25);
    } finally {
        process.off('uncaughtException', collect);
    }

    assert.deepEqual(
        uncaught.map(err => err.message),
        []
    );

    handler = (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('still alive');
    };
    assert.equal((await get()).body, 'still alive');
};

test('the origin status code is passed through', async () => {
    for (const status of [200, 201, 204, 301, 404, 418, 500]) {
        handler = (req, res) => {
            res.writeHead(status);
            res.end();
        };

        const res = await get();
        assert.equal(res.status, status, `status ${status}`);
    }
});

test('origin response headers are passed through', async () => {
    handler = (req, res) => {
        res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store',
            ETag: '"abc123"',
            'X-Custom': 'value'
        });
        res.end('{}');
    };

    const res = await get();
    assert.equal(res.headers['content-type'], 'application/json; charset=utf-8');
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.equal(res.headers.etag, '"abc123"');
    assert.equal(res.headers['x-custom'], 'value');
});

test('repeated Set-Cookie headers survive the round trip', async () => {
    handler = (req, res) => {
        res.setHeader('Set-Cookie', ['a=1; Path=/', 'b=2; Path=/; HttpOnly']);
        res.writeHead(200);
        res.end();
    };

    const res = await get();
    assert.deepEqual(res.headers['set-cookie'], ['a=1; Path=/', 'b=2; Path=/; HttpOnly']);
});

test('a redirect Location header is left untouched', async () => {
    handler = (req, res) => {
        res.writeHead(302, { Location: 'https://elsewhere.example.com/target' });
        res.end();
    };

    const res = await get();
    assert.equal(res.status, 302);
    assert.equal(res.headers.location, 'https://elsewhere.example.com/target');
});

test('request headers reach the origin unchanged', async () => {
    let received;
    handler = (req, res) => {
        received = req.headers;
        res.writeHead(200);
        res.end();
    };

    await get('/', {
        headers: {
            authorization: 'Bearer secret-token',
            cookie: 'session=abc',
            'accept-language': 'et-EE',
            'x-request-id': 'req-1'
        }
    });

    assert.equal(received.authorization, 'Bearer secret-token');
    assert.equal(received.cookie, 'session=abc');
    assert.equal(received['accept-language'], 'et-EE');
    assert.equal(received['x-request-id'], 'req-1');
});

test('paths and query strings are forwarded verbatim', async () => {
    const seen = [];
    handler = (req, res) => {
        seen.push(req.url);
        res.writeHead(200);
        res.end();
    };

    const paths = ['/', '/a/b/c', '/search?q=hello%20world&page=2', '/uni%C3%A7ode/path', '/trailing/', '/double//slash'];
    for (const path of paths) {
        await get(path);
    }

    assert.deepEqual(seen, paths);
});

test('all common methods are proxied', async () => {
    const seen = [];
    handler = (req, res) => {
        seen.push(req.method);
        res.writeHead(200);
        res.end();
    };

    for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
        const res = await get('/', { method });
        assert.equal(res.status, 200, method);
    }

    assert.deepEqual(seen, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
});

test('a HEAD request returns headers without a body', async () => {
    handler = (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': '5' });
        res.end();
    };

    const res = await get('/', { method: 'HEAD' });
    assert.equal(res.status, 200);
    assert.equal(res.headers['content-length'], '5');
    assert.equal(res.body, '');
});

test('large request and response bodies are streamed through', async () => {
    const payload = 'x'.repeat(2 * 1024 * 1024);
    let receivedLength = 0;

    handler = (req, res) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => {
            receivedLength = Buffer.concat(chunks).length;
            res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
            res.end(payload);
        });
    };

    const res = await get('/upload', {
        method: 'POST',
        headers: { 'content-type': 'application/octet-stream' },
        body: payload
    });

    assert.equal(receivedLength, payload.length);
    assert.equal(res.body.length, payload.length);
});

test('a chunked response is delivered in order', async () => {
    handler = (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        let index = 0;
        const tick = () => {
            if (index === 5) {
                return res.end('done');
            }
            res.write(`chunk-${index++} `);
            setImmediate(tick);
        };
        tick();
    };

    const res = await get('/stream');
    assert.equal(res.body, 'chunk-0 chunk-1 chunk-2 chunk-3 chunk-4 done');
    assert.equal(res.headers['transfer-encoding'], 'chunked');
});

test('the 502 page is served when the origin refuses the connection', async () => {
    config.proxy.origin = 'http://127.0.0.1:1/';

    const res = await get();
    assert.equal(res.status, 502);
    assert.match(res.headers['content-type'], /^text\/html/);
    assert.match(res.body, /Something went wrong/);
});

test('the 502 page is served when the origin hostname does not resolve', async () => {
    config.proxy.origin = 'http://origin.invalid/';

    const res = await get();
    assert.equal(res.status, 502);
    assert.match(res.body, /Something went wrong/);
});

test('an origin that drops the connection mid-response does not take the worker down', async () => {
    handler = (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.write('partial');
        // hard reset while the response is still open
        res.socket.destroy();
    };

    await assertSurvives(() => get('/truncated').catch(err => err));
});

test('a client that disconnects early does not take the worker down', async () => {
    handler = (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.write('start');
        // never finishes, the client gives up first
    };

    await assertSurvives(
        () =>
            new Promise(resolve => {
                const req = http.request(`${front.url}/hang`, { headers: { host: 'proxy.example.com' } }, res => {
                    res.once('data', () => {
                        req.destroy();
                        resolve();
                    });
                });
                req.once('error', () => resolve());
                req.end();
            })
    );
});

test('configured response headers are applied on top of the origin headers', async () => {
    config.proxy.headers = [{ key: 'server', value: 'https-front' }];
    handler = (req, res) => {
        res.writeHead(200, { Server: 'origin-server', 'X-From-Origin': 'yes' });
        res.end();
    };

    const res = await get();
    assert.equal(res.headers.server, 'https-front');
    assert.equal(res.headers['x-from-origin'], 'yes');
});
