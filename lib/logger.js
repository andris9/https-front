'use strict';

const config = require('@zone-eu/wild-config');
const pino = require('pino');
const { alabelDomain, hasOneSpelling, unicodeDomain } = require('./tools');

// The fields a domain name is logged under. A name reaches a log line either
// already normalized to A-labels, which is how the certificate store and the
// rest of this application spell it, or straight off the wire in whatever
// spelling the client sent, so the same domain shows up two ways across the log.
// Logs are read by people, so the name is put into its Unicode spelling on the
// way out, in one place rather than at every call site, and the A-label follows
// it in `<field>Alabel`: that is what the certificate, the Redis keys and the
// CA's own logs carry, so it stays there to be searched for.
const domainKeys = ['domain', 'subdomain', 'servername', 'altNames'];

// The two spellings of what a field holds, in the shape the field holds them,
// or null when there is nothing to rewrite: not a name, a name with one
// spelling, or an A-label that does not decode and so has no other. `alabel` is
// null on its own when it matches the Unicode spelling, so that an entry never
// carries the same name twice. Nearly every name has one spelling, and that is
// what keeps the access log line, written once per proxied request, from being
// taken apart and rebuilt for nothing.
const spellings = value => {
    const names = typeof value === 'string' ? [value] : value;
    if (!Array.isArray(names) || !names.every(name => typeof name === 'string') || names.every(hasOneSpelling)) {
        return null;
    }

    // Encoded from the name as it was decoded, not from the one that arrived.
    // That saves the decode, which is the expensive half, and for a name whose
    // decode ran out of passes it prints the A-label of what the rest of the code
    // saw rather than of a name one pass further along that nothing acted on.
    const unicode = names.map(unicodeDomain);
    const alabel = unicode.map(alabelDomain);
    const matches = other => unicode.every((name, i) => name === other[i]);

    if (matches(names) && matches(alabel)) {
        return null;
    }

    const asField = list => (typeof value === 'string' ? list[0] : list);
    return { unicode: asField(unicode), alabel: matches(alabel) ? null : asField(alabel) };
};

const formatDomains = obj => {
    let rewrites = null;

    for (const key of domainKeys) {
        const spelling = spellings(obj[key]);
        if (spelling) {
            rewrites = rewrites || new Map();
            rewrites.set(key, spelling);
        }
    }

    if (!rewrites) {
        return obj;
    }

    // Rebuilt rather than written to, since the caller may still hold the object
    // it logged, and rebuilt in key order so that the A-label follows the name it
    // belongs to instead of landing at the end of the line.
    const formatted = {};
    for (const key of Object.keys(obj)) {
        const rewrite = rewrites.get(key);
        formatted[key] = rewrite ? rewrite.unicode : obj[key];

        if (rewrite && rewrite.alabel) {
            formatted[`${key}Alabel`] = rewrite.alabel;
        }
    }

    return formatted;
};

// One logger for the process, so the log level is set in a single place. Every
// module takes a child of it, tagged with the component it belongs to.
const logger = pino({
    level: (config.log && config.log.level) || 'info',
    formatters: { log: formatDomains }
});

const componentLogger = component => logger.child({ app: 'https-front', component });

module.exports = {
    logger,
    componentLogger,

    // Internals exposed for the test suite only, not part of the public API.
    testables: {
        formatDomains
    }
};
