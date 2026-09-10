'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { normalizeDomain, unicodeDomain, isValidDomain, normalizeIp, getHostname } = require('../lib/tools');

test('normalizeDomain', async t => {
    await t.test('lowercases and trims', () => {
        assert.equal(normalizeDomain('  ExAmPle.COM  '), 'example.com');
    });

    await t.test('converts unicode domains to punycode', () => {
        assert.equal(normalizeDomain('täst.de'), 'xn--tst-qla.de');
        assert.equal(normalizeDomain('ÄÖÜ.example.com'), 'xn--4ca0bs.example.com');
    });

    await t.test('leaves ascii domains untouched', () => {
        assert.equal(normalizeDomain('sub.example.com'), 'sub.example.com');
        assert.equal(normalizeDomain('xn--tst-qla.de'), 'xn--tst-qla.de');
    });

    await t.test('canonicalizes an A-label the way the certificate store does', () => {
        // Both of these decode to the same name, and the store would file them
        // under one record, so they have to arrive as one name here too
        assert.equal(normalizeDomain('xn--victim-27f.example.com'), 'xn--victim-97f.example.com');
        assert.equal(normalizeDomain('xn--victim-97f.example.com'), 'xn--victim-97f.example.com');

        // The Kelvin sign lowercases to a plain k, so this A-label is the name
        // the store would order for. It must be what gets validated as well.
        assert.equal(normalizeDomain('xn--ban-0k1a.app.example.com'), 'bank.app.example.com');
    });

    await t.test('is stable, so a normalized name normalizes to itself', () => {
        for (const name of ['täst.de', 'xn--ban-0k1a.app.example.com', 'ÄÖÜ.example.com', 'sub.example.com']) {
            assert.equal(normalizeDomain(normalizeDomain(name)), normalizeDomain(name), name);
        }
    });

    await t.test('leaves an A-label that does not decode as it is', () => {
        // punycode.toUnicode throws on each of these rather than returning them
        assert.equal(normalizeDomain('xn--0.example.com'), 'xn--0.example.com');
        assert.equal(normalizeDomain('xn--9999999999999999999a.example.com'), 'xn--9999999999999999999a.example.com');
        assert.equal(normalizeDomain('XN---.example.com'), 'xn---.example.com');
    });

    await t.test('handles empty and non-string input', () => {
        assert.equal(normalizeDomain(''), '');
        assert.equal(normalizeDomain(null), '');
        assert.equal(normalizeDomain(undefined), '');
        assert.equal(normalizeDomain(false), '');
        assert.equal(normalizeDomain(123), '123');
    });
});

test('unicodeDomain', async t => {
    await t.test('decodes A-labels back to the characters they stand for', () => {
        assert.equal(unicodeDomain('xn--tst-qla.de'), 'täst.de');
        assert.equal(unicodeDomain('xn--4ca0bs.example.com'), 'äöü.example.com');
    });

    await t.test('canonicalizes a name that arrived as unicode', () => {
        assert.equal(unicodeDomain('  TÄST.de '), 'täst.de');
    });

    await t.test('leaves ascii domains untouched', () => {
        assert.equal(unicodeDomain('sub.example.com'), 'sub.example.com');
    });

    await t.test('is the decoded half of normalizeDomain, so both agree on the name', () => {
        for (const name of ['täst.de', 'xn--tst-qla.de', 'xn--ban-0k1a.app.example.com', 'ÄÖÜ.example.com', 'sub.example.com']) {
            assert.equal(normalizeDomain(unicodeDomain(name)), normalizeDomain(name), name);
        }
    });

    await t.test('leaves an A-label that does not decode as it is', () => {
        assert.equal(unicodeDomain('xn--0.example.com'), 'xn--0.example.com');
        assert.equal(unicodeDomain('xn--9999999999999999999a.example.com'), 'xn--9999999999999999999a.example.com');
        assert.equal(unicodeDomain('XN---.example.com'), 'xn---.example.com');
    });

    await t.test('handles empty and non-string input', () => {
        assert.equal(unicodeDomain(''), '');
        assert.equal(unicodeDomain(null), '');
        assert.equal(unicodeDomain(undefined), '');
        assert.equal(unicodeDomain(123), '123');
    });
});

test('isValidDomain', async t => {
    await t.test('accepts names that can hold a certificate', () => {
        assert.equal(isValidDomain('example.com'), true);
        assert.equal(isValidDomain('sub.example.com'), true);
        assert.equal(isValidDomain(normalizeDomain('täst.de')), true);
    });

    await t.test('turns down an A-label that does not decode', () => {
        // Joi passes these, since they are well formed as ASCII, but no
        // certificate can be ordered for a name the CA cannot decode either
        assert.equal(isValidDomain('xn--0.example.com'), false);
        assert.equal(isValidDomain('xn--9999999999999999999a.example.com'), false);
    });

    await t.test('turns down what is not a domain at all', () => {
        assert.equal(isValidDomain('not a domain'), false);
        assert.equal(isValidDomain(''), false);
    });
});

test('normalizeIp', async t => {
    await t.test('returns IPv4 addresses as is', () => {
        assert.equal(normalizeIp('1.2.3.4'), '1.2.3.4');
        assert.equal(normalizeIp('  127.0.0.1 '), '127.0.0.1');
    });

    await t.test('strips the IPv4-mapped IPv6 prefix', () => {
        assert.equal(normalizeIp('::ffff:1.2.3.4'), '1.2.3.4');
        assert.equal(normalizeIp('::FFFF:192.168.1.1'), '192.168.1.1');
        assert.equal(normalizeIp('0:0:0:0:0:ffff:8.8.8.8'), '8.8.8.8');
    });

    await t.test('compresses IPv6 addresses', () => {
        assert.equal(normalizeIp('2001:0db8:0000:0000:0000:0000:0000:0001'), '2001:db8::1');
        assert.equal(normalizeIp('::1'), '::1');
    });

    await t.test('handles empty and unparseable input', () => {
        assert.equal(normalizeIp(''), '');
        assert.equal(normalizeIp(null), '');
        assert.equal(normalizeIp(undefined), '');
        // not an IP address, returned lowercased and trimmed
        assert.equal(normalizeIp(' NotAnIp '), 'notanip');
    });
});

test('getHostname', async t => {
    await t.test('uses the Host header without the port', () => {
        assert.equal(getHostname({ headers: { host: 'Example.com:8443' } }), 'example.com');
        assert.equal(getHostname({ headers: { host: 'example.com' } }), 'example.com');
    });

    await t.test('punycodes unicode host headers', () => {
        assert.equal(getHostname({ headers: { host: 'täst.de:443' } }), 'xn--tst-qla.de');
    });

    await t.test('falls back to the HTTP/2 authority', () => {
        assert.equal(getHostname({ headers: {}, authority: 'foo.example.com:443' }), 'foo.example.com');
    });

    await t.test('falls back to the connecting IP', () => {
        assert.equal(getHostname({ headers: {}, ip: '1.2.3.4' }), '1.2.3.4');
    });

    await t.test('prefers the Host header over authority and ip', () => {
        assert.equal(
            getHostname({
                headers: { host: 'example.com' },
                authority: 'other.example.com',
                ip: '1.2.3.4'
            }),
            'example.com'
        );
    });

    await t.test('returns an empty string when nothing identifies the host', () => {
        assert.equal(getHostname({ headers: {} }), '');
        assert.equal(getHostname({ headers: { host: '' } }), '');
    });
});
