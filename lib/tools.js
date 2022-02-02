'use strict';

const ipaddr = require('ipaddr.js');
const net = require('net');
const punycode = require('punycode/');

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

module.exports = { normalizeDomain, normalizeIp, getHostname };
