#!/usr/bin/perl

# Tests for the proxy auth internal variable fallback build.

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

my $t = Test::Nginx->new()->has(qw/http rewrite ngx_expr_module
	ngx_http_proxy_auth_internal_module/);

plan(skip_all => 'variable fallback build required')
	if $t->has_module('ngx_http_proxy_filter_module');

$t->plan(7);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        expr special str_eq $arg_mode special;

        proxy_auth_internal_secret base;

        location = /basic {
            return 200 $proxy_auth_internal_fingerprint;
        }

        location = /disabled {
            proxy_auth_internal off;
            return 200 $proxy_auth_internal_fingerprint;
        }

        location = /conditional {
            when special {
                proxy_auth_internal_secret selected;
            }

            proxy_auth_internal_secret fallback;
            return 200 $proxy_auth_internal_fingerprint;
        }

        location = /order {
            proxy_auth_internal_secret first;

            when special {
                proxy_auth_internal_secret second;
            }

            return 200 $proxy_auth_internal_fingerprint;
        }

        location /inherit/ {
            proxy_auth_internal_secret inherited;

            location = /inherit/child {
                return 200 $proxy_auth_internal_fingerprint;
            }
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  no-secret;

        location / {
            return 200 "[$proxy_auth_internal_fingerprint]";
        }
    }
}

EOF

$t->run();

###############################################################################

fingerprint_ok(auth_body('/basic'), 'base',
	'variable generates a fingerprint from the configured secret');
fingerprint_ok(auth_body('/disabled'), 'base',
	'variable remains available when direct injection is disabled');
fingerprint_ok(auth_body('/conditional?mode=special'), 'selected',
	'matching condition selects the variable secret');
fingerprint_ok(auth_body('/conditional?mode=other'), 'fallback',
	'condition miss selects the fallback variable secret');
fingerprint_ok(auth_body('/order?mode=special'), 'first',
	'first unconditional variable secret wins');
fingerprint_ok(auth_body('/inherit/child'), 'inherited',
	'variable secret inherits into a nested location');
is(auth_body('/', 8082), '[]', 'variable is empty without a secret');

###############################################################################

sub fingerprint_ok {
	my ($value, $secret, $name) = @_;

	my ($timestamp, $digest) = $value =~ /^([0-9a-f]{8})([0-9a-f]{32})$/;
	my $valid = defined $timestamp
		&& md5_hex($secret . $timestamp) eq $digest;

	ok($valid, $name);
}


sub auth_body {
	my ($uri, $port) = @_;
	$port ||= 8080;

	return http_content(http_get($uri,
		PeerAddr => '127.0.0.1:' . port($port)));
}

###############################################################################
