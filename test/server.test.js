'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');

const { closeDb, config, flushTestDb, isPortFree, redisClient, request, startServer, tlsConnect, waitFor } = require('./helpers');

const ROOT = path.join(__dirname, '..');
const HTTP_PORT = config.http.port;
const HTTPS_PORT = config.https.port;

const waitForFreePort = port => waitFor(() => isPortFree(port), { timeout: 10000 });

// Boots the real entry point, the same way the Dockerfile does, and resolves
// once a worker reports that it is listening. The application is stopped and its
// ports released when the test that started it ends.
const startApplication = (t, env) =>
    new Promise((resolve, reject) => {
        const child = spawn(process.execPath, ['server.js'], {
            cwd: ROOT,
            // the child needs real logs: the assertions read its output
            env: Object.assign({}, process.env, { NODE_ENV: 'test', appconf_log_level: 'info' }, env),
            stdio: ['ignore', 'pipe', 'pipe']
        });

        t.after(async () => {
            if (child.exitCode === null) {
                child.kill('SIGKILL');
            }
            await waitForFreePort(HTTP_PORT);
            await waitForFreePort(HTTPS_PORT);
        });

        let output = '';
        const timer = setTimeout(() => {
            child.kill('SIGKILL');
            reject(new Error(`Server did not start in time. Output:\n${output}`));
        }, 20000);

        let started = false;
        const onData = chunk => {
            output += chunk.toString();
            if (!started && /Server started/.test(output)) {
                started = true;
                clearTimeout(timer);
                resolve({
                    child,
                    output: () => output,
                    // 'close' rather than 'exit', so the last log lines are read
                    // before the result is inspected
                    stop: signal =>
                        new Promise(done => {
                            child.once('close', (code, sig) => done({ code, signal: sig }));
                            child.kill(signal || 'SIGTERM');
                        })
                });
            }
        };

        child.stdout.on('data', onData);
        child.stderr.on('data', chunk => (output += chunk.toString()));
        child.once('error', err => {
            clearTimeout(timer);
            reject(err);
        });
    });

let origin;

test.before(async () => {
    await flushTestDb();
    origin = await startServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('origin reached');
    });
});

test.after(async () => {
    await origin.close();
    await closeDb();
});

test('the cluster boots, serves both protocols and shuts down on SIGTERM', async t => {
    assert.ok(await isPortFree(HTTP_PORT), `port ${HTTP_PORT} must be free before the test`);

    const app = await startApplication(t, { appconf_proxy_origin: `${origin.url}/` });

    assert.match(app.output(), /Master process started/);
    assert.match(app.output(), /Worker came online/);

    // plain HTTP is proxied to the origin
    const res = await request(`http://127.0.0.1:${HTTP_PORT}/`, { headers: { host: 'boot.example.com' } });
    assert.equal(res.status, 200);
    assert.equal(res.body, 'origin reached');

    // HTTPS answers with the default certificate for an unknown server name
    const handshake = await tlsConnect({ port: HTTPS_PORT, servername: 'boot.example.com' }, socket => socket.getPeerCertificate());
    assert.match(handshake.subject.CN, /https-front/);

    const exit = await app.stop('SIGTERM');
    assert.equal(exit.code, 0);
    assert.match(app.output(), /Received SIGTERM/);

    assert.ok(await waitForFreePort(HTTP_PORT), `port ${HTTP_PORT} was not released`);
    assert.ok(await waitForFreePort(HTTPS_PORT), `port ${HTTPS_PORT} was not released`);
});

test('SIGINT shuts the cluster down just as cleanly', async t => {
    const app = await startApplication(t, { appconf_proxy_origin: `${origin.url}/` });

    const exit = await app.stop('SIGINT');
    assert.equal(exit.code, 0);
    assert.match(app.output(), /Received SIGINT/);
    assert.match(app.output(), /Closing the application/);
});

test('a worker that dies is replaced', async t => {
    const app = await startApplication(t, { appconf_proxy_origin: `${origin.url}/` });

    const workerPid = Number(app.output().match(/"worker":(\d+)/)[1]);
    process.kill(workerPid, 'SIGKILL');

    // The master waits before forking a replacement, and the new worker is only
    // usable once it reports that it is listening again.
    const replacement = await waitFor(() => {
        const pids = [...app.output().matchAll(/"msg":"Worker came online","worker":(\d+)/g)].map(match => Number(match[1]));
        const pid = pids.find(entry => entry !== workerPid);
        return pid && app.output().match(/Server started/g).length > 1 ? pid : null;
    });

    assert.ok(replacement, `no replacement worker started serving. Output:\n${app.output()}`);
    assert.match(app.output(), /Worker died/);

    // and the replacement serves traffic again
    const res = await request(`http://127.0.0.1:${HTTP_PORT}/`, { headers: { host: 'respawn.example.com' } });
    assert.equal(res.status, 200);
});

test('TLS sessions are stored in Redis so they can be resumed by any worker', async t => {
    await startApplication(t, { appconf_proxy_origin: `${origin.url}/` });

    // TLSv1.2 is requested explicitly: session ID based resumption is what the
    // newSession/resumeSession handlers in worker.js implement.
    const connect = session =>
        tlsConnect({ port: HTTPS_PORT, servername: 'session.example.com', maxVersion: 'TLSv1.2', session }, socket => ({
            reused: socket.isSessionReused(),
            session: socket.getSession()
        }));

    const first = await connect();
    assert.equal(first.reused, false);
    assert.ok(first.session, 'a session was issued');

    // give the newSession handler time to write to Redis
    const stored = await waitFor(async () => {
        const keys = await redisClient.keys('tls:*');
        return keys.length ? keys : null;
    });
    assert.ok(stored, 'the TLS session was stored in Redis');

    const second = await connect(first.session);
    assert.equal(second.reused, true, 'the stored session was resumed');
});
