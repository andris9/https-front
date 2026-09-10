'use strict';

// A domain name reaches the log either as an A-label, which is how the
// certificate store and the rest of this application spell it, or straight off
// the wire in whatever spelling the client sent. The log is the one place a name
// is read by a person, so it is spelled in Unicode there either way, with the
// A-label next to it for anything that has to be searched for or matched up
// against the certificate.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { closeDb, logRecords } = require('./helpers');
const { testables } = require('../lib/logger');
const { formatDomains } = testables;

test.after(closeDb);

test('log domain formatting', async t => {
    await t.test('decodes an A-label and keeps it alongside', () => {
        assert.deepEqual(formatDomains({ msg: 'Proxy access', domain: 'xn--tst-qla.de' }), {
            msg: 'Proxy access',
            domain: 'täst.de',
            domainAlabel: 'xn--tst-qla.de'
        });
    });

    await t.test('canonicalizes a name that arrived as unicode', () => {
        assert.deepEqual(formatDomains({ servername: '  TÄST.de ' }), { servername: 'täst.de', servernameAlabel: 'xn--tst-qla.de' });
    });

    await t.test('covers every field a name is logged under', () => {
        assert.deepEqual(
            formatDomains({
                domain: 'xn--tst-qla.de',
                subdomain: 'xn--tst-qla.de',
                servername: 'xn--tst-qla.de',
                altNames: ['xn--tst-qla.de', 'plain.example.com']
            }),
            {
                domain: 'täst.de',
                domainAlabel: 'xn--tst-qla.de',
                subdomain: 'täst.de',
                subdomainAlabel: 'xn--tst-qla.de',
                servername: 'täst.de',
                servernameAlabel: 'xn--tst-qla.de',
                altNames: ['täst.de', 'plain.example.com'],
                altNamesAlabel: ['xn--tst-qla.de', 'plain.example.com']
            }
        );
    });

    await t.test('writes the A-label next to the name it belongs to', () => {
        const entry = formatDomains({ msg: 'Proxy access', ip: '1.2.3.4', domain: 'xn--tst-qla.de', url: '/', response: 200 });
        assert.deepEqual(Object.keys(entry), ['msg', 'ip', 'domain', 'domainAlabel', 'url', 'response']);
    });

    await t.test('leaves an ascii name alone, since it has one spelling', () => {
        const entry = { msg: 'Proxy access', domain: 'sub.example.com', altNames: ['sub.example.com'] };
        assert.equal(formatDomains(entry), entry);
    });

    await t.test('leaves entries without a name as they are', () => {
        // `domains` is a count of them, not one of them
        const entry = { msg: 'Starting a renewal pass', domains: 12, ip: '1.2.3.4', url: '/xn--tst-qla' };
        assert.equal(formatDomains(entry), entry);
    });

    await t.test('leaves a name that does not decode as it is', () => {
        // the log is not the place to find out that punycode.toUnicode throws
        for (const domain of ['xn--0.example.com', 'xn--9999999999999999999a.example.com', 'xn---.example.com']) {
            const entry = { msg: 'SNI handler', domain };
            assert.equal(formatDomains(entry), entry, domain);
        }
    });

    await t.test('does not write to the object it was handed', () => {
        const entry = { msg: 'Proxy access', domain: 'xn--tst-qla.de' };
        formatDomains(entry);
        assert.equal(entry.domain, 'xn--tst-qla.de');
        assert.equal(entry.domainAlabel, undefined);
    });

    await t.test('is wired into the process logger', () => {
        const script = "require('./lib/logger').componentLogger('test').info({ msg: 'entry', domain: 'xn--tst-qla.de' });";
        const out = execFileSync(process.execPath, ['-e', script], {
            cwd: path.join(__dirname, '..'),
            // the suite silences the log, so this one process is given a level
            env: Object.assign({}, process.env, { appconf_log_level: 'info' }),
            encoding: 'utf-8'
        });

        const [entry] = logRecords(out);
        assert.equal(entry.domain, 'täst.de');
        assert.equal(entry.domainAlabel, 'xn--tst-qla.de');
    });
});
