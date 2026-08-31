# HTTPS Front

Simple HTTP/HTTPS proxy server that generously tries to set up LE HTTP certificates for any domain.

Main use case - you want to expose the same origin via unknown amount of domain names that might require HTTPS.

## Features

- All requests, no matter the domain name, are proxied to a single configured origin
- HTTPS certificates get generated on first request
- Certificates are renewed for active domain names only, once two thirds of the
  certificate lifetime has passed, so the shorter certificates Let's Encrypt is
  moving to are handled without a configuration change
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

Certificates are renewed once two thirds of their lifetime has passed, which is
the timing Let's Encrypt recommends for clients that do not implement ARI. The
window follows each certificate instead of being a fixed number of days, because
Let's Encrypt is shortening certificate lifetimes: 90 days today, 64 days from
2027-02-10 and 45 days from 2028-02-16, with the opt-in `tlsserver` profile
already issuing 45 day certificates. A fixed "renew with 30 days left" rule would
ask for a renewal a third of the way into a 45 day certificate, on every request.

In practice that means a 90 day certificate is renewed with 30 days left, a 64 day
one with about 21 days left and a 45 day one with 15 days left.

Renewal happens in the background while the current certificate keeps being
served. If a renewal fails, a failsafe lock blocks further attempts for an hour
and the existing certificate stays in use until it expires.

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
