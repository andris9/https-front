'use strict';

const ipaddr = require('ipaddr.js');
const Joi = require('joi');
const net = require('net');
const punycode = require('punycode/');

// Built once: this runs on the TLS handshake path, where the schema was
// previously rebuilt for every connection.
const domainSchema = Joi.string().domain({ tlds: { allow: true } });

// True for a name that can hold a certificate. Expects an already normalized
// domain, so it pairs with normalizeDomain above.
const isValidDomain = domain => !domainSchema.validate(domain).error;

const normalizeDomain = domain => {
    domain = (domain || '').toString().toLowerCase().trim();
    try {
        if (/[\x80-\uFFFF]/.test(domain)) {
            domain = punycode.toASCII(domain);
        }
    } catch (E) {
        // ignore
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

module.exports = { normalizeDomain, normalizeIp, getHostname, isValidDomain };
