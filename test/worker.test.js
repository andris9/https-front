'use strict';

// What the worker does when something it depends on is broken: the ports are
// taken, the service user does not exist, or the worker crashes outright. All of
// it runs against the real entry point.

const test = require('node:test');
const assert = require('node:assert/strict');

const { closeDb, config, flushTestDb, startApplication, startServer } = require('./helpers');

const HTTP_PORT = config.http.port;
const HTTPS_PORT = config.https.port;

test.before(async () => {
    await flushTestDb();
});

test.after(async () => {
    await closeDb();
});

test('a port that is already taken fails the boot instead of running half started', async t => {
    for (const [proto, port] of [
        ['http', HTTP_PORT],
        ['https', HTTPS_PORT]
    ]) {
        await t.test(`the ${proto} port is in use`, async t2 => {
            const blocker = await startServer(undefined, port);

            // a safety net if an assertion below throws
            t2.after(() => blocker.close());

            const app = await startApplication(t2, { ready: /Failed to start server/ });

            // the listener that lost reports the conflict
            assert.ok(
                app.records().some(record => record.msg === 'Web server error' && record.proto === proto && record.err.code === 'EADDRINUSE'),
                `no EADDRINUSE reported for ${proto}. Output:\n${app.output()}`
            );

            // and the worker gives up rather than serving on one protocol only
            await app.waitForLog(/"msg":"Worker died"/);
            assert.ok(
                app.records().some(record => record.msg === 'Worker died' && record.code === 1),
                `the master did not see the worker fail. Output:\n${app.output()}`
            );

            // stop the application before freeing the port, so the master cannot
            // grab it on its way out, and so teardown has nothing left to wait for
            await app.stop('SIGTERM');
            await blocker.close();
        });
    }
});

test('a service group that does not exist is fatal, and the worker never reports itself started', async t => {
    const app = await startApplication(t, {
        env: { appconf_proxy_group: 'no-such-group-here' },
        ready: /Failed to change group/
    });

    const fatal = app.records().find(record => record.msg === 'Failed to change group');
    assert.equal(fatal.group, 'no-such-group-here');
    assert.equal(fatal.level, 60, 'logged as fatal');

    // privileges are dropped before the worker reports itself ready
    assert.ok(!app.records().some(record => record.msg === 'Server started'));
});

test('a service user that does not exist is fatal, and the worker never reports itself started', async t => {
    const app = await startApplication(t, {
        env: { appconf_proxy_user: 'no-such-user-here' },
        ready: /Failed to change user/
    });

    const fatal = app.records().find(record => record.msg === 'Failed to change user');
    assert.equal(fatal.user, 'no-such-user-here');
    assert.equal(fatal.level, 60, 'logged as fatal');

    assert.ok(!app.records().some(record => record.msg === 'Server started'));
});

test('a worker that crashes on startup is reported and replaced', async t => {
    // the default certificate cannot be read, so requiring the worker throws
    const app = await startApplication(t, {
        env: { appconf_https_key: './setup/does-not-exist.pem' },
        ready: /uncaughtException/
    });

    const crash = app.records().find(record => record.msg === 'uncaughtException');
    assert.match(crash.err.message, /ENOENT/, 'the crash is the unreadable key, not something else');

    // the master notices and keeps trying
    await app.waitForLog(/"msg":"Worker died"/);
});
