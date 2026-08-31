# HTTPS Front

Public-facing HTTP/HTTPS proxy. Every request, whatever the domain name, is
proxied to one configured origin. Certificates for those domains are provisioned
from Let's Encrypt over ACME on first use and stored in Redis, so several
instances can share one certificate pool.

## Layout

| Path                     | Role                                                                      |
| ------------------------ | ------------------------------------------------------------------------- |
| `server.js`              | Cluster master: forks workers, handles signals, respawns dead workers     |
| `worker.js`              | Binds the HTTP and HTTPS ports, keeps TLS sessions in Redis               |
| `lib/app.js`             | Request handler: serves ACME challenges, proxies everything else          |
| `lib/sni.js`             | SNI callback, the per-domain context cache, default certificate fallback  |
| `lib/certs.js`           | ACME account and certificate provisioning, domain validation, Redis state |
| `lib/redis-challenge.js` | `http-01` challenge store used by the ACME client                         |
| `lib/check-url.js`       | Optional external allow/deny hook consulted before provisioning           |
| `lib/proxy-server.js`    | `http-proxy-3` instance, access logging, 502 page                         |
| `lib/tools.js`           | Domain, IP and hostname normalization                                     |
| `lib/logger.js`          | The process logger, one child per component                               |
| `config/default.toml`    | All settings, documented inline                                           |

## Conventions

- CommonJS, `'use strict'`, 4 spaces, single quotes, 160 column width. Prettier
  and ESLint are authoritative: `npm run lint` and `npm run format:check`.
- Configuration comes from [@zone-eu/wild-config](https://github.com/zone-eu/wild-config).
  `config/default.toml` is merged with `config/<NODE_ENV>.toml`, and any value can
  be overridden from the environment as `appconf_<section>_<key>`.
- Logging is pino through `lib/logger.js`: `componentLogger('name')` per module,
  with the level taken from `log.level` in the configuration.
- Redis key prefixes: `acme:account:*`, `acme:certificate:*`, `acme:challenge:*`,
  `tls:*` for TLS session tickets, and `<certKey>:lock` as the failsafe that
  blocks renewal retries for an hour after a failure.
- Certificates are renewed once two thirds of their lifetime has passed, never on
  a fixed number of days left, because Let's Encrypt is shortening certificate
  lifetimes. `renewalTime` in `lib/certs.js` carries the reasoning and the dates.
- A TLS handshake must not look a certificate up in Redis. `lib/sni.js` keeps a
  bounded LRU of secure contexts and revalidates an entry only once
  `https.contextCacheTtl` has passed, which is also what bounds how long a
  renewal takes to reach a worker. (Session resumption in `worker.js` does read
  Redis per handshake, on purpose: that is where the session lives.)

## Tests

`npm test` runs the `node:test` suite in `test/` with `NODE_ENV=test`, which needs
a Redis server on `127.0.0.1:6379`; database 15 is flushed while the suite runs.
`npm run coverage` produces a c8 report.

The suite avoids the network: `startAcmeDirectory()` serves a stub ACME
directory, DNS lookups are replaced with `t.mock.method(resolver, ...)` from
`certs.testables`, and origins and validation endpoints are throwaway `http`
servers. Anything that would order a real certificate is blocked with the
failsafe lock or a stubbed `acme.certificates.create`. Keep it that way: no test
may talk to Let's Encrypt.

Shared fixtures live in `test/helpers.js` (`seedCertificate`, `certKeyFor`,
`startAcmeDirectory`, `startRecordingServer`, `useLocalDomainChecks`, `waitFor`).
Add to it rather than copying a fixture into a second test file.

`lib/certs.js` exports a `testables` object for the suite. It is not public API.

## Releases

release-please in manifest mode (`release-please-config.json`,
`.release-please-manifest.json`). Conventional Commits drive the version bump, and
merging the release PR attaches a deployable tarball to the GitHub release.
Dependencies are refreshed with `npm run update` (ncu plus a fresh lockfile).
