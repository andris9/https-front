# HTTPS Front

Simple HTTP/HTTPS proxy server that generously tries to set up LE HTTP certificates for any domain.

Main use case - you want to expose the same origin via unknown amount of domain names that might require HTTPS.

## Features

- All requests, no matter the domain name, are proxied to a single configured origin
- HTTPS certificates get generated on first request
- Certificates are renewed for active domain names only, once two thirds of the
  certificate lifetime has passed, or earlier when the CA asks for it, so the
  shorter certificates Let's Encrypt is moving to are handled without a
  configuration change
- Certificates are issued against P-256 keys, which every browser supports and
  which makes for a cheaper handshake than RSA
- Orders and domain validations are both rate limited against a budget shared by
  every worker and instance, so a flood of requests for names that have no
  certificate cannot spend an ACME account's whole allowance
- Renewals are ordered on a timer as well as on demand, so a domain that is not
  being asked for still gets renewed before its certificate expires
- All data is stored in Redis, so you can run several instances in different servers that all share the same certificate pool
- TLS sessions are shared through Redis as well, so a resumed session can land on any instance

## Requirements

- Node.js 22 or newer
- Redis

## Usage

### 1. Configure

Edit the [configuration file](config/default.toml).

Any setting can also be overridden from the environment by prefixing the config
path with `appconf_` and replacing the dots with underscores, for example:

```
$ appconf_proxy_origin="http://127.0.0.1:3000/" npm start
```

Environment specific files are merged on top of `default.toml` based on
`NODE_ENV`, so `config/production.toml` is loaded when `NODE_ENV=production`.

Logging goes to stdout as JSON. Set `log.level` (`trace` through `fatal`, or
`silent`) to control how much of it there is.

### 2. Install dependencies

```
$ npm ci --omit=dev
```

### 3. Run the application

**NB!** your service user must have the privileges to use ports 443 and 80

```
$ npm start
```

## Docker

```
$ docker build -t https-front .
$ docker run --rm -p 80:8080 -p 443:8443 https-front
```

## Development

```
$ npm install
$ npm test          # unit and integration tests, needs Redis on 127.0.0.1:6379
$ npm run coverage  # the same suite with a coverage report
$ npm run lint      # ESLint
$ npm run format    # Prettier
```

The test suite runs with `NODE_ENV=test` and uses [`config/test.toml`](config/test.toml),
which points Redis at database 15. That database is flushed while the tests run,
so keep it free of anything you care about. Set `TEST_LOG_LEVEL=info` to see the
application logs while debugging a test.

Dependencies are refreshed in one step:

```
$ npm run update
```

## Releases

Releases are managed by [release-please](https://github.com/googleapis/release-please).
Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
`fix:` produces a patch release, `feat:` a minor one, and `feat!:` or a
`BREAKING CHANGE:` footer a major one. Merging the release PR tags the release,
updates the changelog and attaches a deployable `https-front.tar.gz` bundle to it.

## Certificate Renewal

Certificates come from [@postalsys/certs](https://github.com/postalsys/certs),
which speaks ACME (RFC 8555) over `http-01` challenges and keeps every
certificate, private key and ACME account in Redis.

Certificates are renewed once two thirds of their lifetime has passed. The window
follows each certificate instead of being a fixed number of days, because Let's
Encrypt is shortening certificate lifetimes: 90 days today, 64 days from
2027-02-10 and 45 days from 2028-02-16, with the opt-in `tlsserver` profile
already issuing 45 day certificates. A fixed "renew with 30 days left" rule would
ask for a renewal a third of the way into a 45 day certificate, on every request.

In practice that means a 90 day certificate is renewed with 30 days left, a 64 day
one with about 21 days left and a 45 day one with 15 days left. Where the CA
offers renewal information (RFC 9773), that is asked first and decides instead,
which is how an early renewal after a revocation reaches the proxy.

Renewal happens in the background while the current certificate keeps being
served. A failed attempt, whether the domain stopped validating or the order
itself did not go through, blocks further attempts for five minutes, doubling for
each consecutive failure up to an hour, and the existing certificate stays in use
until it expires.

Renewals are not left to traffic alone. One worker per certificate pool, elected
through Redis, walks the pool on a timer and renews what has fallen due. Without
it a domain quiet enough not to be asked for between its renewal falling due and
its certificate expiring would only be renewed by the first visitor after it had
already stopped working, from inside that visitor's handshake. A tick reads one
slice of the pool rather than all of it, so the cost of a pass does not grow with
the number of domains being fronted. See the `renewal` block in the
[configuration](config/default.toml).

## Rate Limits

Certificate authorities count orders per ACME account, not per server, and Let's
Encrypt allows 300 new orders per account every three hours unless you have asked
for more. A proxy that orders a certificate whenever an unrecognised name arrives
can spend that in a minute: a scanner working through a list of domains is
indistinguishable, at the TLS handshake, from a hundred thousand new customers.

Two token buckets in Redis, shared by every worker and every instance using the
same certificate pool, decide what is allowed to proceed:

- The **validation budget** is spent before the DNS queries and the `checkUrl`
  request that decide whether a domain may have a certificate at all. It is what
  a flood reaches first, and it protects your resolver and your validation
  endpoint rather than the certificate authority.
- The **order budget** is spent after a domain has passed validation, immediately
  before the order. Spending it last is deliberate: names that were never pointed
  at this proxy fail validation and never reach the CA, so they cannot take the
  allowance real domains need.

Both buckets hold a share back, `renewalReserve`, that only a renewal may spend
into. A first issuance that has to wait is a site that is not up yet; a renewal
that waits too long is a site that goes down, so the fleet already in service
gets the last of the budget.

When the certificate authority does report a rate limit, ordering stops for the
whole pool rather than for the one domain that ran into it, because the limit
belongs to the account. Each consecutive report doubles the wait, up to the three
hour window the limit is counted over, and the next successful order resets it.
While the pool is paused, certificates already issued keep being served.

Sizing the order budget is the part worth doing by hand. A fleet of N domains
needs roughly `N / (certificate lifetime * 2/3)` orders per day just to keep
renewing, so 100 000 domains on 90 day certificates need about 1 700 a day, and
about 3 300 a day once lifetimes reach 45 days. Set `acme.limits.ordersPerHour`
from the allowance the CA has actually granted the account, and ask for more if
the arithmetic does not fit inside it.

Each worker keeps a bounded cache of TLS contexts so that a handshake does not
have to read the certificate out of Redis every time. An entry is revalidated
once `https.contextCacheTtl` seconds have passed, so a renewal reaches every
instance within that window.

## Upgrading From 1.4.x

Releases up to 1.4.1 kept certificates in a Redis layout of their own. Nothing
has to be migrated by hand: the ACME account is carried over before the first
order, and a certificate the first time its domain is looked up, so an upgraded
instance keeps serving what it already holds instead of re-ordering it. The old
entries are left where they are and expire on their own.

## Default Certificates

Default certificate files reside in [setup](setup) folder. These are self-signed
placeholders, served only when no certificate matches the requested name. You can
regenerate these by running

```
$ npm run testcerts
```

This will take some time as a new dhparam file is generated as well.

## Security

See [SECURITY.md](SECURITY.md) for the supported versions, how to report a
vulnerability, and the deployment properties worth reviewing.

## License

**MIT**
