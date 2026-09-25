#!/usr/bin/perl

# Tests for ngx_http_proxy_auth_internal_module with proxy filter support.

###############################################################################

use warnings;
use strict;

use Digest::MD5 qw/ md5_hex /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite ngx_expr_module
	ngx_http_proxy_auth_internal_module/);

plan(skip_all => 'proxy filter build required')
	unless $t->has_module('ngx_http_proxy_filter_module');

$t->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8081;
        server_name  backend;

        location / {
            return 200 "$http_x_fingerprint|$http_x_alt";
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        expr special str_eq $arg_mode special;

        proxy_auth_internal on;
        proxy_auth_internal_secret base;

        location = /basic {
            proxy_set_header X-Fingerprint stale;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /off {
            proxy_auth_internal off;
            proxy_set_header X-Fingerprint stale;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /custom-header {
            proxy_auth_internal_header X-Alt;
            proxy_set_header X-Fingerprint stale;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /conditional {
            when special {
                proxy_auth_internal_secret selected;
            }

            proxy_auth_internal_secret fallback;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /order {
            proxy_auth_internal_secret first;

            when special {
                proxy_auth_internal_secret second;
            }

            proxy_pass http://127.0.0.1:8081;
        }

        location = /conditional-enable {
            when special {
                proxy_auth_internal on;
            }

            proxy_auth_internal off;
            proxy_set_header X-Fingerprint stale;
            proxy_pass http://127.0.0.1:8081;
        }

        location /inherit/ {
            proxy_auth_internal_secret inherited;
            proxy_auth_internal_header X-Alt;

            location = /inherit/child {
                proxy_pass http://127.0.0.1:8081;
            }
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  no-secret;

        proxy_auth_internal on;

        location / {
            proxy_set_header X-Fingerprint stale;
            proxy_pass http://127.0.0.1:8081;
        }
    }
}

EOF

$t->run();

###############################################################################

fingerprint_ok(field(auth_body('/basic'), 0), 'base',
	'direct filter replaces an existing fingerprint header');
is(auth_body('/off'), 'stale|',
	'disabled direct filter preserves an existing header');

my $custom = auth_body('/custom-header');
is(field($custom, 0), 'stale', 'custom header leaves the default header alone');
fingerprint_ok(field($custom, 1), 'base',
	'custom header receives the generated fingerprint');

fingerprint_ok(field(auth_body('/conditional?mode=special'), 0), 'selected',
	'matching condition selects its secret');
fingerprint_ok(field(auth_body('/conditional?mode=other'), 0), 'fallback',
	'condition miss selects the fallback secret');
fingerprint_ok(field(auth_body('/order?mode=special'), 0), 'first',
	'first unconditional secret wins over a later condition');

fingerprint_ok(field(auth_body('/conditional-enable?mode=special'), 0), 'base',
	'matching condition enables direct injection');
is(auth_body('/conditional-enable?mode=other'), 'stale|',
	'condition miss selects the disabled fallback');

fingerprint_ok(field(auth_body('/inherit/child'), 1), 'inherited',
	'secret and custom header inherit into a nested location');

is(auth_body('/', 8082), 'stale|',
	'missing secret leaves upstream headers unchanged');

###############################################################################

sub fingerprint_ok {
	my ($value, $secret, $name) = @_;

	my ($timestamp, $digest) = $value =~ /^([0-9a-f]{8})([0-9a-f]{32})$/;
	my $valid = defined $timestamp
		&& md5_hex($secret . $timestamp) eq $digest;

	ok($valid, $name);
}


sub field {
	my ($body, $index) = @_;

	return (split /\|/, $body, -1)[$index];
}


sub auth_body {
	my ($uri, $port) = @_;
	$port ||= 8080;

	return http_content(http_get($uri,
		PeerAddr => '127.0.0.1:' . port($port)));
}

###############################################################################
