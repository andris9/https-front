'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { normalizeDomain, unicodeDomain, alabelDomain, isValidDomain, normalizeIp, getHostname } = require('../lib/tools');
const store = require('@postalsys/certs/lib/tools');

// Awkward names, kept in one place: an A-label after each of the separators
// punycode folds into a dot, one that decodes to a different name than it looks
// like, and the plain cases for company.
const NAMES = [
    'S\u3002xn--tea00ivdq0bn23h2w0x.de',
    'bank\u3002xn--tst-qla.de',
    'bank\uFF0Exn--tst-qla.de',
    'bank\uFF61xn--tst-qla.de',
    't\u00e4st\u3002de',
    'xn--xn--ban-0k1a-.example.com',
    'te\u0301st.com',
    'xn--ban-0k1a.app.example.com',
    'xn--tst-qla.de',
    't\u00e4st.de',
    '\u00c4\u00d6\u00dc.example.com',
    'sub.example.com'
];

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
        for (const name of NAMES) {
            assert.equal(normalizeDomain(normalizeDomain(name)), normalizeDomain(name), name);
        }
    });

    await t.test('decodes a name that is encoded more than once', () => {
        // `xn--xn--ban-0k1a-.example.com` decodes to `xn--ban-0k1a.example.com`,
        // which is still an A-label and decodes again to `bank.example.com`. One
        // pass leaves a name the store would decode a second time on its way to
        // the CA, which is this proxy validating one name and ordering another
        assert.equal(normalizeDomain('xn--xn--ban-0k1a-.example.com'), 'bank.example.com');
        assert.equal(normalizeDomain('de.xn--xn--ban-0k1a-.app'), 'de.bank.app');
    });

    await t.test('composes a name that arrives decomposed', () => {
        assert.equal(normalizeDomain('te\u0301st.com'), normalizeDomain('t\u00e9st.com'));
    });

    await t.test('canonicalizes an A-label after any separator punycode folds', () => {
        // U+3002, U+FF0E and U+FF61 end a label just as the dot does. An A-label
        // that follows one has to go through the same round trip, or the name is
        // validated here as itself and ordered by the store as something else:
        // `s\u3002xn--tea00ivdq0bn23h2w0x.de` would be ordered as
        // `s.xn--tea00ivdq0bn23hk20x.de`
        assert.equal(normalizeDomain('S\u3002xn--tea00ivdq0bn23h2w0x.de'), 's.xn--tea00ivdq0bn23hk20x.de');
        assert.equal(normalizeDomain('bank\u3002xn--tst-qla.de'), 'bank.xn--tst-qla.de');
        assert.equal(normalizeDomain('bank\uFF0Exn--tst-qla.de'), 'bank.xn--tst-qla.de');
        assert.equal(normalizeDomain('bank\uFF61xn--tst-qla.de'), 'bank.xn--tst-qla.de');
        assert.equal(normalizeDomain('t\u00e4st\u3002de'), 'xn--tst-qla.de');
    });

    await t.test('agrees with the certificate store on the name it will order', () => {
        // The store canonicalizes the name again on its way to the CA. This is
        // the invariant the round trip exists for, and it fails loudly here if
        // either side of it moves.
        for (const name of NAMES) {
            const ours = normalizeDomain(name);
            assert.equal(store.toAsciiDomain(store.normalizeDomain(ours)), ours, name);
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

    await t.test('decodes until nothing is left encoded', () => {
        assert.equal(unicodeDomain('xn--xn--ban-0k1a-.example.com'), 'bank.example.com');
    });

    await t.test('composes a name that arrives decomposed', () => {
        assert.equal(unicodeDomain('te\u0301st.com'), 't\u00e9st.com');
    });

    await t.test('folds the separators punycode treats as label ends', () => {
        assert.equal(unicodeDomain('t\u00e4st\u3002de'), 't\u00e4st.de');
        assert.equal(unicodeDomain('bank\u3002xn--tst-qla.de'), 'bank.t\u00e4st.de');
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

    await t.test('turns down a name the decode could not finish', () => {
        // More levels of encoding than unicodeDomain makes passes, so what comes
        // back is still an A-label and the store, which starts with a budget of
        // its own, would decode the rest on its way to the CA. Validating one
        // name and ordering another is the one thing the round trip is for.
        //
        // The second name is what that looks like as an attack: every level is a
        // legal hostname label, because the Kelvin sign in the payload makes
        // punycode emit a delta suffix instead of the bare trailing hyphen that
        // Joi would have rejected, and it collapses to a plain `k` on the way
        // down. The handshake path normalizes in lib/sni.js and again in
        // lib/certs.js, so one pass is not the end of it.
        for (const nested of [
            'xn--xn--xn--xn--xn--xn--bank------.example.com',
            'xn--xn--xn--xn--xn--xn--xn--xn--xn--xn--xn--ban-01a-----8p2t-----.example.com'
        ]) {
            const half = normalizeDomain(nested);
            assert.notEqual(normalizeDomain(half), half, nested);
            assert.equal(isValidDomain(half), false, nested);

            // Normalizing again does converge in the end, and the name is fine to
            // accept once it has, so what has to hold is not that it is turned
            // down forever but that it is never accepted while the store would
            // still order something else.
            let domain = nested;
            for (let pass = 0; pass < 4; pass++) {
                domain = normalizeDomain(domain);
                if (isValidDomain(domain)) {
                    assert.equal(store.toAsciiDomain(store.normalizeDomain(domain)), domain, nested);
                }
            }
        }
    });

    await t.test('accepts the spelling the certificate store keeps as well', () => {
        // The renewal pass reads its domains from the store, which holds them
        // with their A-labels decoded
        assert.equal(isValidDomain('täst.de'), true);
        assert.equal(isValidDomain('xn--tst-qla.de'), true);
    });

    await t.test('turns down what is not a domain at all', () => {
        assert.equal(isValidDomain('not a domain'), false);
        assert.equal(isValidDomain(''), false);
    });
});

test('alabelDomain', async t => {
    await t.test('encodes a decoded name back to the wire form', () => {
        assert.equal(alabelDomain('täst.de'), 'xn--tst-qla.de');
        assert.equal(alabelDomain('sub.example.com'), 'sub.example.com');
    });

    await t.test('is the other half of normalizeDomain', () => {
        for (const name of NAMES) {
            assert.equal(alabelDomain(unicodeDomain(name)), normalizeDomain(name), name);
        }
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
