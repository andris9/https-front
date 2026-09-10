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
| `lib/certs.js`           | Domain validation, admission control, the store of `@postalsys/certs`     |
| `lib/rate-limit.js`      | The Redis token buckets and backoff markers admission control is built on |
| `lib/renewal-sweeper.js` | The timed renewal pass, run by one elected worker per pool                |
| `lib/legacy-certs.js`    | Imports the certificates and ACME account of releases up to 1.4.x         |
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
  with the level taken from `log.level` in the configuration. A name reaches a log
  line either as an A-label, which is how everything else here spells it, or off
  the wire as the client sent it, so a pino `formatters.log` hook in that module
  puts the fields carrying one (`domain`, `subdomain`, `servername`, `altNames`)
  through `unicodeDomain` on the way out, and writes the A-label next to it in
  `<field>Alabel` when the two spellings differ. Log lines are read by people, and
  one domain should read one way, but the A-label is what the certificate, the
  Redis keys and the CA's own logs carry, so it stays greppable. Errors thrown with
  a name in the message spell it the same way, through `unicodeDomain` as well.
- ACME, the certificate store and the renewal schedule are
  [@postalsys/certs](https://github.com/postalsys/certs). `lib/certs.js` only adds
  the domain validation this proxy does before it is willing to order, and the
  decision of what to serve while an order runs.
- Redis key prefixes: everything the store writes lives under
  `acme:<acme.key>:certs:*` (the settings hash, the domain list, challenges and
  the per-domain locks), and `tls:*` holds the TLS session tickets. Under the
  same `acme:<acme.key>` prefix this application writes its own bookkeeping,
  which the store knows nothing about: `blocked:<domain>` and `failures:<domain>`
  are the marker for a domain whose last attempt failed and the count behind it,
  `paused` and `paused:failures` are the same pair for the whole pool after the
  CA reported a rate limit, `budget:orders` and `budget:validations` are the two
  token buckets, and `renewal:leader` is the lease for the renewal pass. All of
  them are spelled through `poolKey()` in `lib/certs.js`. The `acme:account:*`
  and `acme:certificate:*` hashes of earlier releases are only ever read, by
  `lib/legacy-certs.js`.
- Nothing orders a certificate without spending from a budget first, because the
  CA counts orders per ACME account and this proxy is fronting far more domains
  than one account is allowed to order for in a burst. `lib/certs.js` spends
  twice: once for `validateDomain`, which is what a flood of names that were
  never pointed here reaches first, and once for the order itself, after the
  domain has passed validation, so that names failing validation cannot take the
  order budget. Both buckets keep a `renewalReserve` share back for renewals,
  because a first issuance that waits is a site that is not up yet while a
  renewal that waits is a site that goes down.
- A rate limit is a property of the account rather than of the domain that ran
  into it, so `urn:ietf:params:acme:error:rateLimited` stops ordering for the
  whole pool through the `paused` key, doubling for each consecutive one. Do not
  time that pause from the error's `retryAfter`: the ACME client caps it at a
  minute before it arrives, because it also uses it as a polling delay.
- The per-domain block doubles too, and jumps straight to the full hour for
  anything the CA answered, because the store has already armed its own hour long
  failsafe for those and re-validating underneath it is pure waste.
- Renewals are ordered by `lib/renewal-sweeper.js` on a timer as well as by
  traffic, since a domain quiet enough not to be asked for between its renewal
  falling due and its certificate expiring would otherwise be renewed from inside
  the first handshake after it had already stopped working. One tick reads one
  slice of the pool, not the whole of it.
- `normalizeDomain` in `lib/tools.js` canonicalizes a name the way the certificate
  store does, by decoding A-labels and composing them, and then encodes the result
  back to A-labels. That is what keeps the name this proxy validates the same as
  the name the order carries: without the round trip `xn--ban-0k1a.example.com`
  is checked as itself and ordered as `bank.example.com`. Which names take that
  trip is decided by `hasOneSpelling`, not by looking for an A-label at a label
  boundary, because punycode ends a label on the ideographic and fullwidth stops
  as well as on the dot: spelling that set out here is how the guard went stale
  once already, decoding `xn--tst-qla.de` but not `bank。xn--tst-qla.de`. A test
  in `test/tools.test.js` runs the awkward names through the store's own
  canonicalization and fails if the two ever disagree. Decoding runs to a fixpoint
  for the same reason: `xn--xn--ban-0k1a-.example.com` decodes to
  `xn--ban-0k1a.example.com`, which is still an A-label, and one pass here plus
  another in the store is again two different names. The fixpoint is what
  `isValidDomain` insists on rather than what the decode loop's bound promises: a
  name that is neither spelling of itself is one the loop ran out of passes on, and
  the store, which starts with a fresh budget of its own, would carry on decoding
  it. Names nest deeply enough to reach that bound, so it is a rejection rather
  than a formality.
- Certificates are renewed once two thirds of their lifetime has passed, never on
  a fixed number of days left, because Let's Encrypt is shortening certificate
  lifetimes. The rule, and the RFC 9773 renewal information that overrides it,
  live in the store rather than here.
- A TLS handshake must not look a certificate up in Redis. `lib/sni.js` keeps a
  bounded LRU of secure contexts and revalidates an entry only once
  `https.contextCacheTtl` has passed, which is also what bounds how long a
  renewal takes to reach a worker. (Session resumption in `worker.js` does read
  Redis per handshake, on purpose: that is where the session lives.)
- Domains with nothing stored are remembered in a second cache in `lib/sni.js`,
  not among the contexts. One shared LRU meant a run of names with no
  certificate evicted a live context each, so a scan working through a list of
  domains emptied every worker's cache behind it and left each real handshake
  afterwards reading Redis and parsing a certificate again.

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
rather than copying a fixture into a second test file. `useLimits`,
`useRenewalSettings` and `setBudget` are the ones for admission control: the
budgets in `config/test.toml` are wide enough that no test runs into one by
accident, so a test about a budget narrows it itself.

`lib/certs.js` and `lib/renewal-sweeper.js` export a `testables` object for the
suite. It is not public API.

## Releases

release-please in manifest mode (`release-please-config.json`,
`.release-please-manifest.json`). Conventional Commits drive the version bump, and
merging the release PR attaches a deployable tarball to the GitHub release.
Dependencies are refreshed with `npm run update` (ncu plus a fresh lockfile).
