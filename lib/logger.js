'use strict';

const config = require('@zone-eu/wild-config');
const pino = require('pino');

// One logger for the process, so the log level is set in a single place. Every
// module takes a child of it, tagged with the component it belongs to.
const logger = pino({ level: (config.log && config.log.level) || 'info' });

const componentLogger = component => logger.child({ app: 'https-front', component });

module.exports = { logger, componentLogger };
