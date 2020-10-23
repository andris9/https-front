'use strict';

const httpProxy = require('http-proxy');
const log = require('npmlog');

const proxyServer = httpProxy.createProxyServer({});

proxyServer.on('proxyReq', (proxyReq, req) => {
    proxyReq.setHeader('X-Forwarded-Proto', req.proto);
    proxyReq.setHeader('X-Connecting-IP', req.ip);
    req.stats = {
        time: Date.now()
    };
});

proxyServer.on('proxyRes', (proxyReq, req) => {
    log.http('Proxy', `c=%s p=%s d=%s u=%s t=%sms s=%s`, req.ip, req.proto, req.domain, req.url, Date.now() - req.stats.time, proxyReq.statusCode);
});

proxyServer.on('error', (err, req, res) => {
    res.writeHead(500, {
        'Content-Type': 'text/plain'
    });
    res.end('Something went wrong. And we are reporting a custom error message.');
    log.http('Proxy', `c=%s p=%s d=%s u=%s t=%sms s=%s e=%s`, req.ip, req.proto, req.domain, req.url, Date.now() - req.stats.time, 502, err.message);
});

module.exports = { proxyServer };
