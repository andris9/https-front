# HTTPS Front

Public-facing HTTP/HTTPS proxy. Every request, whatever the domain name, is
proxied to one configured origin. Certificates for those domains are provisioned
from Let's Encrypt over ACME on first use and stored in Redis, so several
instances can share one certificate pool.

## Layout

| Path                  | Role                                                                     |
| --------------------- | ------------------------------------------------------------------------ |
| `server.js`           | Cluster master: forks workers, handles signals, respawns dead workers    |
| `worker.js`           | Binds the HTTP and HTTPS ports, keeps TLS sessions in Redis              |
| `lib/app.js`          | Request handler: serves ACME challenges, proxies everything else         |
| `lib/sni.js`          | SNI callback, the per-domain context cache, default certificate fallback |
| `lib/certs.js`        | Domain validation, and the certificate store of `@postalsys/certs`       |
| `lib/legacy-certs.js` | Imports the certificates and ACME account of releases up to 1.4.x        |
| `lib/check-url.js`    | Optional external allow/deny hook consulted before provisioning          |
| `lib/proxy-server.js` | `http-proxy-3` instance, access logging, 502 page                        |
| `lib/tools.js`        | Domain, IP and hostname normalization                                    |
| `lib/logger.js`       | The process logger, one child per component                              |
| `config/default.toml` | All settings, documented inline                                          |

## Conventions

- CommonJS, `'use strict'`, 4 spaces, single quotes, 160 column width. Prettier
  and ESLint are authoritative: `npm run lint` and `npm run format:check`.
- Configuration comes from [@zone-eu/wild-config](https://github.com/zone-eu/wild-config).
  `config/default.toml` is merged with `config/<NODE_ENV>.toml`, and any value can
  be overridden from the environment as `appconf_<section>_<key>`.
- Logging is pino through `lib/logger.js`: `componentLogger('name')` per module,
  with the level taken from `log.level` in the configuration.
- ACME, the certificate store and the renewal schedule are
  [@postalsys/certs](https://github.com/postalsys/certs). `lib/certs.js` only adds
  the domain validation this proxy does before it is willing to order, and the
  decision of what to serve while an order runs.
- Redis key prefixes: everything the store writes lives under
  `acme:<acme.key>:certs:*` (the settings hash, the domain list, challenges and
  the per-domain locks), `acme:<acme.key>:blocked:<domain>` is the only key
  `lib/certs.js` writes itself and marks a domain whose last attempt failed, and
  `tls:*` holds the TLS session tickets. The
  `acme:account:*` and `acme:certificate:*` hashes of earlier releases are only
  ever read, by `lib/legacy-certs.js`.
- `normalizeDomain` in `lib/tools.js` canonicalizes a name the way the certificate
  store does, by decoding A-labels and composing them, and then encodes the result
  back to A-labels. That is what keeps the name this proxy validates the same as
  the name the order carries: without the round trip `xn--ban-0k1a.example.com`
  is checked as itself and ordered as `bank.example.com`.
- Certificates are renewed once two thirds of their lifetime has passed, never on
  a fixed number of days left, because Let's Encrypt is shortening certificate
  lifetimes. The rule, and the RFC 9773 renewal information that overrides it,
  live in the store rather than here.
- A TLS handshake must not look a certificate up in Redis. `lib/sni.js` keeps a
  bounded LRU of secure contexts and revalidates an entry only once
  `https.contextCacheTtl` has passed, which is also what bounds how long a
  renewal takes to reach a worker. (Session resumption in `worker.js` does read
  Redis per handshake, on purpose: that is where the session lives.)

## Tests

`npm test` runs the `node:test` suite in `test/` with `NODE_ENV=test`, which needs
a Redis server on `127.0.0.1:6379`; database 15 is flushed while the suite runs.
`npm run coverage` produces a c8 report.

The suite avoids the network: `stubAcme()` replaces every exchange with the
certificate authority, DNS lookups are replaced with `t.mock.method(resolver, ...)`
from `certs.testables`, and origins and validation endpoints are throwaway `http`
servers. Anything that would order a real certificate is blocked with the
failsafe lock or a stubbed `createCertificate`. Keep it that way: no test may
talk to Let's Encrypt.

Shared fixtures live in `test/helpers.js` (`stubAcme`, which also answers the
CAA lookup, `seedCertificate`, `seedLegacyCertificate`, `issueCertificate`,
`blockKey`, `startRecordingServer`, `useLocalDomainChecks`, `waitFor`). Add to it
rather than copying a fixture into a second test file.

`lib/certs.js` exports a `testables` object for the suite. It is not public API.

## Releases

release-please in manifest mode (`release-please-config.json`,
`.release-please-manifest.json`). Conventional Commits drive the version bump, and
merging the release PR attaches a deployable tarball to the GitHub release.
Dependencies are refreshed with `npm run update` (ncu plus a fresh lockfile).
