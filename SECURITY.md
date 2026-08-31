# Security Policy

HTTPS Front is a public-facing HTTP/HTTPS proxy. It terminates TLS for arbitrary
domain names, provisions Let's Encrypt certificates over an ACME flow, and keeps
certificate private keys in Redis. Because it is exposed to untrusted traffic and
handles private keys, security reports are taken seriously and answered quickly.

## Supported Versions

Security fixes are released only against the latest version. Patches are not
backported, so upgrading to the current release line is the supported way to
receive security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Report privately through one of the following channels:

1. **GitHub Security Advisories (preferred).** Open a private report at
   <https://github.com/andris9/https-front/security/advisories/new>. The
   discussion stays private until a fix is published, and you can be credited.
2. **Email.** Send details to **andris@kreata.ee**.

Please include as much of the following as you can:

- The affected version and environment (release or commit, Node.js version, OS).
- The configuration that triggers the issue, with secrets removed.
- A description of the impact, and steps or a proof of concept that reproduces it.

You can expect an acknowledgement within a few business days and an assessment
with a planned fix date once the report has been reproduced.

## Deployment Notes

A few properties of this service are worth keeping in mind when reviewing it:

- **Any domain pointed at the server can request a certificate.** That is the
  intended behaviour. Restrict who can do so with the `precheck` DNS rules and the
  `checkUrl` validation hook in [`config/default.toml`](config/default.toml),
  otherwise anyone who points a DNS record at the host consumes ACME rate limits.
- **Redis holds certificate private keys and ACME account keys.** It must not be
  reachable from untrusted networks, and it should be protected with
  authentication and TLS when it is not on localhost.
- **The process needs privileged ports.** Bind ports 80 and 443 and then drop
  privileges with the `proxy.user` and `proxy.group` settings, or grant the
  capability instead of running as root.
- **The bundled certificate in [`setup`](setup) is a self-signed placeholder.**
  It is served only when no certificate matches the requested name, and it is not
  a secret. Regenerate it with `npm run testcerts`.
