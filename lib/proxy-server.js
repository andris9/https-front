'use strict';

const httpProxy = require('http-proxy');
const config = require('wild-config');
const fs = require('fs');

const pino = require('pino')();
const logger = pino.child({ app: 'https-front', component: 'proxy' });

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
    logger.info({
        msg: `Proxy access`,
        remoteAddress: req.ip,
        protocol: req.proto,
        domain: req.domain,
        url: req.url,
        time: Date.now() - req.stats.time,
        response: proxyReq.statusCode
    });
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

    logger.info({
        msg: `Proxy error`,
        remoteAddress: req.ip,
        protocol: req.proto,
        domain: req.domain,
        url: req.url,
        time: Date.now() - req.stats.time,
        response: 502,
        err
    });
});

module.exports = { proxyServer };
