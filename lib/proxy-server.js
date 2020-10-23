'use strict';

const httpProxy = require('http-proxy');
const log = require('npmlog');
const config = require('wild-config');
const fs = require('fs');

const error502 = fs.readFileSync(config.proxy.error502, 'utf-8');

const proxyServer = httpProxy.createProxyServer({});

proxyServer.on('proxyReq', (proxyReq, req) => {
    proxyReq.setHeader('X-Forwarded-Proto', req.proto);
    proxyReq.setHeader('X-Connecting-IP', req.ip);
    req.stats = {
        time: Date.now()
    };
});

proxyServer.on('proxyRes', (proxyReq, req, res) => {
    log.http('Proxy', `c=%s p=%s d=%s u=%s t=%sms s=%s`, req.ip, req.proto, req.domain, req.url, Date.now() - req.stats.time, proxyReq.statusCode);
    if (config?.proxy?.headers?.length) {
        for (let header of config.proxy.headers) {
            if (header?.key && header?.value) {
                res.setHeader(header.key, header.value);
            }
        }
    }
});

proxyServer.on('error', (err, req, res) => {
    res.writeHead(502, {
        'Content-Type': 'text/html'
    });

    res.end(error502);

    log.http('Proxy', `c=%s p=%s d=%s u=%s t=%sms s=%s e=%s`, req.ip, req.proto, req.domain, req.url, Date.now() - req.stats.time, 502, err.message);
});

module.exports = { proxyServer };
