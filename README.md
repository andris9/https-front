# HTTPS Front

Simple HTTP/HTTPS proxy server that generously tries to set up LE HTTP certificates for any domain.

## Features

-   All requests, no matter the domain name, are proxied to a single configured origin
-   HTTPS requests get certificate generated on first request
-   Certificates are renewed for active domain names only
-   All data is stored in Redis, so you can run several instances in different servers that all share the same certificate pool

## Usage

### 1. Configure

Edit the [configuration file](config/default.toml).

### 2. Install dependencies

```
$ npm install --production
```

### 3. Run the application

**NB!** your service user must have the privileges to use ports 443 and 80

```
$ npm start
```

## License

**MIT**
