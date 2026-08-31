'use strict';

const httpProxy = require('http-proxy-3');
const config = require('@zone-eu/wild-config');
const fs = require('fs');

const { componentLogger } = require('./logger');
const logger = componentLogger('proxy');

const error502 = fs.readFileSync(config.proxy.error502, 'utf-8');

const proxyServer = httpProxy.createProxyServer({});

proxyServer.on('proxyReq', (proxyReq, req) => {
    proxyReq.setHeader('X-Forwarded-Proto', req.proto);
    proxyReq.setHeader('X-Connecting-IP', req.ip);
});

// Time since the request entered the app, stamped in app.js.
const elapsed = req => (req.stats ? Date.now() - req.stats.time : 0);

proxyServer.on('proxyRes', (proxyRes, req) => {
    logger.info({
        msg: `Proxy access`,
        remoteAddress: req.ip,
        protocol: req.proto,
        domain: req.domain,
        url: req.url,
        userAgent: req.headers['user-agent'] || '',
        time: elapsed(req),
        response: proxyRes.statusCode
    });
    if (config?.proxy?.headers?.length) {
        for (let header of config.proxy.headers) {
            if (header?.key && header?.value) {
                // The origin's headers are copied onto the response after this
                // event, so the configured value is written there rather than
                // onto the response, where the copy would overwrite it.
                proxyRes.headers[header.key.toLowerCase()] = header.value;
            }
        }
    }
});

proxyServer.on('error', (err, req, res) => {
    res.writeHead(502, {
        'Content-Type': 'text/html'
    });

    res.end(error502);

    logger.info({
        msg: `Proxy error`,
        remoteAddress: req.ip,
        protocol: req.proto,
        domain: req.domain,
        url: req.url,
        userAgent: req.headers['user-agent'] || '',
        time: elapsed(req),
        response: 502,
        err
    });
});

module.exports = { proxyServer };
