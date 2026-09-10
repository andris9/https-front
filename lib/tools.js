'use strict';

const ipaddr = require('ipaddr.js');
const Joi = require('joi');
const net = require('net');
const punycode = require('punycode/');

// Built once: this runs on the TLS handshake path, where the schema was
// previously rebuilt for every connection.
const domainSchema = Joi.string().domain({ tlds: { allow: true } });

// The A-labels of a name decoded, or null for one that is not an A-label at all:
// `xn--0.example.com` is not valid punycode and
// `xn--9999999999999999999a.example.com` overflows the decoder, and
// punycode.toUnicode throws on both rather than handing them back. Every decode
// here goes through this, so that what does not decode is one rule rather than
// two, and a name with no A-label costs one regex test.
const decodeAlabels = domain => {
    if (!/(^|\.)xn--/.test(domain)) {
        return domain;
    }

    try {
        return punycode.toUnicode(domain);
    } catch (E) {
        return null;
    }
};

// True for a name that can hold a certificate. Expects an already normalized
// domain, so it pairs with normalizeDomain above. Joi passes an undecodable
// A-label, since it is well formed as ASCII, and nothing can hold a certificate
// for a name the CA cannot read either, so the decoder has a say as well.
const isValidDomain = domain => !domainSchema.validate(domain).error && decodeAlabels(domain) !== null;

// Domain names arrive in whatever spelling the client chose, and the certificate
// store canonicalizes them its own way: an A-label is decoded back to Unicode,
// composed and lowercased. That decoded name is the one canonical spelling of a
// domain in this application, so both the name the store files a record under
// and the name the logs print are built from it.
const unicodeDomain = domain => {
    domain = (domain || '').toString().toLowerCase().trim();

    const decoded = decodeAlabels(domain);
    if (decoded === null) {
        // Nothing arrived that has a Unicode spelling, the case isValidDomain
        // turns down above. The name is left as it came and shown that way.
        return domain;
    }

    return decoded.normalize('NFC').toLowerCase().trim();
};

// The canonical name encoded back to A-labels, which is what the store files a
// record under and what the order it places carries. A name is put through the
// same round trip here, so that the name this proxy validates, caches and blocks
// on is the name the store will use. Skipping the decode would let
// `xn--ban-0k1a.example.com` be validated as itself and ordered as
// `bank.example.com`, which is a certificate for a domain that never passed the
// checks in lib/certs.js.
const normalizeDomain = domain => {
    domain = unicodeDomain(domain);

    if (/[\x80-\uFFFF]/.test(domain)) {
        try {
            domain = punycode.toASCII(domain);
        } catch (E) {
            // Nothing encodable arrived, same as above: the name is left as it
            // came and turned down later.
        }
    }

    return domain;
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

module.exports = { coalesce, normalizeDomain, unicodeDomain, normalizeIp, getHostname, isValidDomain };
