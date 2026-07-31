# ngx_http_proxy_auth_internal_module

`ngx_http_proxy_auth_internal_module` generates an internal authentication
fingerprint for proxied requests.

When `NGX_HTTP_PROXY_FILTER` is available, the module registers a proxy request
filter and writes the configured proxy header directly. The fingerprint variable
is always available and can be used with `proxy_set_header` when proxy filter is
not enabled.

## Synopsis

```nginx
http {
    proxy_auth_internal on;
    proxy_auth_internal_secret secret1;
    proxy_auth_internal_header X-Fingerprint;

    server {
        location / {
            proxy_set_header X-Fingerprint $proxy_auth_internal_fingerprint;
            proxy_pass http://upstream;
        }
    }
}
```

## Installation

```sh
./configure --add-module=/path/to/ngx_http_proxy_auth_internal_module
```

When using proxy filter direct header injection, add `ngx_http_proxy_filter_module`
before this module.

## Directives

### proxy_auth_internal

**Syntax:** `proxy_auth_internal on | off;`

**Default:** `proxy_auth_internal off;`

**Context:** `http`, `server`, `location`, `when`

Enables or disables direct proxy request header injection when proxy filter is
available.

### proxy_auth_internal_secret

**Syntax:** `proxy_auth_internal_secret secret;`

**Default:** `-`

**Context:** `http`, `server`, `location`, `when`

Configures the secret used to generate fingerprints.

### proxy_auth_internal_header

**Syntax:** `proxy_auth_internal_header header;`

**Default:** `proxy_auth_internal_header X-Fingerprint;`

**Context:** `http`, `server`, `location`, `when`

Sets the upstream request header used for generated fingerprints.

## Variables

### $proxy_auth_internal_fingerprint

Generates a fingerprint in the format `<8-character timestamp><32-character MD5>`.
The timestamp is hexadecimal UNIX time, and the MD5 is computed from the secret
concatenated with the timestamp.

## License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
