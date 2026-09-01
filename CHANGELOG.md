# Changelog

## [1.4.1](https://github.com/andris9/https-front/compare/v1.4.0...v1.4.1) (2026-09-01)


### Miscellaneous Chores

* release 1.4.1 ([4cd2694](https://github.com/andris9/https-front/commit/4cd2694280ebb383c04bcf912deabc00449e89b4))

## [1.4.0](https://github.com/andris9/https-front/compare/v1.3.2...v1.4.0) (2026-08-31)


### Features

* **certs:** renew certificates at two thirds of their lifetime ([2ea8115](https://github.com/andris9/https-front/commit/2ea81153112168d41514ff52955b927aeab38e62))
* **log:** make the log level configurable ([329d8ec](https://github.com/andris9/https-front/commit/329d8ec8e3206faa05047f370c70367fdf66a080))
* **proxy:** move to http-proxy-3 and make configured headers stick ([693293e](https://github.com/andris9/https-front/commit/693293ebfaeabfd8b2b6e003be0b3079cf292162))


### Bug Fixes

* **certs:** remember a domain that fails validation ([37335e1](https://github.com/andris9/https-front/commit/37335e110c82af6b47dc2543fdff99db53e9a823))
* **check-url:** send the configured path and the domain with GET requests ([953d816](https://github.com/andris9/https-front/commit/953d816916a424282db305a55c39f8bf639b6e15))
* **cluster:** replace a worker that dies instead of exiting ([1e15b31](https://github.com/andris9/https-front/commit/1e15b31fa8701b0c13b00e8d912927661cd3cb6e))


### Performance Improvements

* **sni:** serve a TLS handshake without reading Redis ([8a2f577](https://github.com/andris9/https-front/commit/8a2f5778b7ee1496e38cf0f6f07ac11aefaa8ea6))

## [1.3.2](https://github.com/andris9/https-front/compare/v1.3.1...v1.3.2) (2023-10-05)


### Bug Fixes

* **deploy:** changed env to vars ([a968d17](https://github.com/andris9/https-front/commit/a968d173a8d0a052ef4efa4a968ab25d1b489f3e))
* **deploy:** changed env to vars ([b638759](https://github.com/andris9/https-front/commit/b6387595e2f85ac3d9c6de417f908dea62376abe))

## [1.3.1](https://github.com/andris9/https-front/compare/v1.3.0...v1.3.1) (2023-10-05)


### Bug Fixes

* **deploy:** updated release script ([44a35bf](https://github.com/andris9/https-front/commit/44a35bf908b863e19123b3d348886a553ad0f92c))

## [1.3.0](https://github.com/andris9/https-front/compare/v1.2.1...v1.3.0) (2023-10-05)


### Features

* **deploy:** added automatic release management ([927c5c3](https://github.com/andris9/https-front/commit/927c5c3c477ee31fe7c0b897579b760d778047c7))
