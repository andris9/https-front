'use strict';

const ipaddr = require('ipaddr.js');
const Joi = require('joi');
const net = require('net');
const punycode = require('punycode/');

// Built once: this runs on the TLS handshake path, where the schema was
// previously rebuilt for every connection.
const domainSchema = Joi.string().domain({ tlds: { allow: true } });

// A name that carries an A-label contains this somewhere. Deliberately not
// anchored to a label boundary: punycode ends a label on the ideographic and
// fullwidth stops as well as on the ASCII one, and writing that set out here is
// how the boundary test went stale before, decoding `xn--tst-qla.de` but not
// `bank\u3002xn--tst-qla.de`. The loose test only ever asks punycode to look at
// a name it would have left alone anyway.
const A_LABEL = /xn--/;

// What has to be encoded before it can be a name on the wire. A separator
// punycode folds into a dot is itself outside ASCII, so this catches those too.
const NON_ASCII = /[\x80-\uFFFF]/;

// True for a name that is spelled a single way: nothing to decode, nothing to
// encode and no separator to fold, so its Unicode spelling and its A-labels are
// both the name itself. Nearly every name is one of these, and this is what
// keeps them off the two conversions below.
const hasOneSpelling = domain => !A_LABEL.test(domain) && !NON_ASCII.test(domain);

// How many times a name is decoded before the attempt to reach a fixpoint is
// given up on. A pass either reaches one or strips a level of encoding, and a
// level costs five octets, so a 63 octet label can carry twelve of them: the
// bound is reachable, not a formality. A name that needs more passes than this
// comes back half converted, and isValidDomain turns that down rather than let
// it through as a name the store would go on decoding.
const MAX_DECODE_PASSES = 5;

// A name with its A-labels decoded and its separators folded into dots, or null
// for an A-label that is not one: `xn--0.example.com` is not valid punycode and
// `xn--9999999999999999999a.example.com` overflows the decoder, and
// punycode.toUnicode throws on both rather than handing them back.
const decodeAlabels = domain => {
    try {
        return punycode.toUnicode(domain);
    } catch (E) {
        return null;
    }
};

// Domain names arrive in whatever spelling the client chose, and the certificate
// store canonicalizes them its own way: an A-label is decoded back to Unicode,
// composed and lowercased. That decoded name is the one canonical spelling of a
// domain in this application, so both the name the store files a record under
// and the name the logs print are built from it.
const unicodeDomain = domain => {
    domain = (domain || '').toString().toLowerCase().trim();

    // A decoded name can hold an A-label of its own: `xn--xn--ban-0k1a-.example.com`
    // decodes to `xn--ban-0k1a.example.com`, which decodes again to
    // `bank.example.com`. Stopping after one pass leaves a name that whoever
    // normalizes it next does not agree with, and the certificate store normalizes
    // again on its way to the CA, so this proxy would validate one name and order
    // another. Decoding runs to a fixpoint for that reason.
    for (let pass = 0; pass < MAX_DECODE_PASSES && !hasOneSpelling(domain); pass++) {
        const decoded = decodeAlabels(domain);
        if (decoded === null) {
            // Nothing arrived that has a Unicode spelling, the case
            // isValidDomain turns down below. The name is left as it came and
            // shown that way.
            break;
        }

        const composed = decoded.normalize('NFC').toLowerCase().trim();
        if (composed === domain) {
            break;
        }

        domain = composed;
    }

    return domain;
};

// The other half: a name encoded back to A-labels, which is what goes on the
// wire. The log formatter asks for this one on its own, having already paid for
// the decode. Takes what unicodeDomain returns, so it does not coerce again.
const alabelDomain = domain => {
    if (!NON_ASCII.test(domain)) {
        return domain;
    }

    try {
        return punycode.toASCII(domain);
    } catch (E) {
        // Nothing encodable arrived, same as above: the name is left as it came
        // and turned down later.
        return domain;
    }
};

// The two halves together are the round trip the certificate store makes as
// well, which is what keeps the name this proxy validates, caches and blocks on
// the same as the name the store files a record under and the order carries.
// Skipping the decode would let `xn--ban-0k1a.example.com` be validated as
// itself and ordered as `bank.example.com`, which is a certificate for a domain
// that never passed the checks in lib/certs.js.
const normalizeDomain = domain => alabelDomain(unicodeDomain(domain));

// True for a name that can hold a certificate. Expects a name that has already
// been through normalizeDomain, or the store's own spelling of one, which is the
// same name with its A-labels left decoded.
const isValidDomain = domain => {
    if (domainSchema.validate(domain).error) {
        return false;
    }

    if (hasOneSpelling(domain)) {
        return true;
    }

    // Joi passes an undecodable A-label, since it is well formed as ASCII, and
    // nothing can hold a certificate for a name the CA cannot read either.
    if (decodeAlabels(domain) === null) {
        return false;
    }

    // A name that is neither spelling of itself is one the decode did not finish,
    // having run out of passes. The store would carry on decoding it on its way
    // to the CA, so letting it through here is validating one name and ordering
    // another, which is the one thing the round trip is for.
    return domain === unicodeDomain(domain) || domain === normalizeDomain(domain);
};

const normalizeIp = ip => {
    ip = (ip || '').toString().toLowerCase().trim();

    if (/^[a-f0-9:]+:(\d+\.){3}\d+$/.test(ip)) {
        // remove pseudo IPv6 prefix
        ip = ip.replace(/^[a-f0-9:]+:((\d+\.){3}\d+)$/, '$1');
    }

    if (net.isIPv6(ip)) {
        // use the short version
        return ipaddr.parse(ip).toString();
    }

    return ip;
};

/**
 * Runs `start` for `key` unless it is already running, so that callers arriving
 * while it is in flight wait on the same promise instead of starting a second
 * one. The entry is cleared once it settles, a rejection included.
 *
 * @param {Map} pending map the caller keeps for its own in-flight work
 * @param {String} key what the work is keyed by, a domain name here
 * @param {Function} start starts the work and returns a promise
 * @returns {Promise} the promise for `key`, shared with everyone else waiting
 */
const coalesce = (pending, key, start) => {
    let current = pending.get(key);
    if (!current) {
        current = start().finally(() => pending.delete(key));
        pending.set(key, current);
    }
    return current;
};

const getHostname = req => {
    let host =
        []
            .concat(req.headers.host || [])
            .concat(req.authority || [])
            .concat(req.ip || [])
            .shift() || '';
    host = host.split(':').shift();

    if (host) {
        host = normalizeDomain(host);
    }

    return host;
};

module.exports = { coalesce, normalizeDomain, unicodeDomain, alabelDomain, hasOneSpelling, normalizeIp, getHostname, isValidDomain };
