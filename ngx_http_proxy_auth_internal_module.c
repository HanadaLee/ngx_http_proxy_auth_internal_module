/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#if (NGX_HTTP_PROXY_FILTER)
#include <ngx_http_proxy_filter_module.h>
#endif


typedef struct {
    ngx_flag_t     enable;
    ngx_str_t      secret;
    ngx_str_t      header_name;
} ngx_http_proxy_auth_internal_loc_conf_t;


static ngx_int_t ngx_http_proxy_auth_internal_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_proxy_auth_internal_fingerprint_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_proxy_auth_internal_build_fingerprint(
    ngx_http_request_t *r, ngx_str_t *fingerprint);
static ngx_str_t ngx_http_proxy_auth_internal_compute_md5_hex(
    ngx_http_request_t *r, const u_char *data, size_t len);
static void *ngx_http_proxy_auth_internal_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxy_auth_internal_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_proxy_auth_internal_init(ngx_conf_t *cf);

#if (NGX_HTTP_PROXY_FILTER)
static ngx_int_t ngx_http_proxy_auth_internal_request_filter(
    ngx_http_request_t *r, ngx_http_proxy_filter_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_auth_internal_set_header(ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *key, ngx_str_t *value);
#endif


static ngx_command_t  ngx_http_proxy_auth_internal_commands[] = {

    { ngx_string("proxy_auth_internal"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_internal_loc_conf_t, enable),
      NULL },

    { ngx_string("proxy_auth_internal_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_internal_loc_conf_t, secret),
      NULL },

    { ngx_string("proxy_auth_internal_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_internal_loc_conf_t, header_name),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_proxy_auth_internal_module_ctx = {
    ngx_http_proxy_auth_internal_add_variables,    /* preconfiguration */
    ngx_http_proxy_auth_internal_init,             /* postconfiguration */

    NULL,                                          /* create main config */
    NULL,                                          /* init main config */

    NULL,                                          /* create server config */
    NULL,                                          /* merge server config */

    ngx_http_proxy_auth_internal_create_loc_conf,  /* create loc config */
    ngx_http_proxy_auth_internal_merge_loc_conf    /* merge loc config */
};


ngx_module_t  ngx_http_proxy_auth_internal_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_auth_internal_module_ctx,      /* module context */
    ngx_http_proxy_auth_internal_commands,         /* module directives */
    NGX_HTTP_MODULE,                               /* module type */
    NULL,                                          /* init master */
    NULL,                                          /* init module */
    NULL,                                          /* init process */
    NULL,                                          /* init thread */
    NULL,                                          /* exit thread */
    NULL,                                          /* exit process */
    NULL,                                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_proxy_auth_internal_vars[] = {

    { ngx_string("proxy_auth_internal_fingerprint"), NULL,
      ngx_http_proxy_auth_internal_fingerprint_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    ngx_http_null_variable
};


static ngx_int_t
ngx_http_proxy_auth_internal_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_proxy_auth_internal_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_auth_internal_fingerprint_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_int_t  rc;
    ngx_str_t  fingerprint;

    rc = ngx_http_proxy_auth_internal_build_fingerprint(r, &fingerprint);
    if (rc != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = fingerprint.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = fingerprint.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_auth_internal_build_fingerprint(ngx_http_request_t *r,
    ngx_str_t *fingerprint)
{
    uint32_t                                    timestamp;
    size_t                                      data_len;
    u_char                                     *fingerprint_data;
    u_char                                      timestamp_hex[9];
    ngx_str_t                                   md5;
    ngx_http_proxy_auth_internal_loc_conf_t    *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_auth_internal_module);

    if (plcf->secret.len == 0) {
        return NGX_DECLINED;
    }

    timestamp = (uint32_t) ngx_time();
    ngx_sprintf(timestamp_hex, "%08xi", timestamp);

    data_len = plcf->secret.len + 8;
    fingerprint_data = ngx_pnalloc(r->pool, data_len);
    if (fingerprint_data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(fingerprint_data, plcf->secret.data, plcf->secret.len);
    ngx_memcpy(fingerprint_data + plcf->secret.len, timestamp_hex, 8);

    md5 = ngx_http_proxy_auth_internal_compute_md5_hex(r, fingerprint_data,
                                                       data_len);
    if (md5.len != 32 || md5.data == NULL) {
        return NGX_ERROR;
    }

    fingerprint->len = 40;
    fingerprint->data = ngx_pnalloc(r->pool, fingerprint->len);
    if (fingerprint->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(fingerprint->data, timestamp_hex, 8);
    ngx_memcpy(fingerprint->data + 8, md5.data, 32);

    return NGX_OK;
}


static ngx_str_t
ngx_http_proxy_auth_internal_compute_md5_hex(ngx_http_request_t *r,
    const u_char *data, size_t len)
{
    ngx_md5_t  md5;
    u_char     digest[16];
    ngx_str_t  md5_hex;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, data, len);
    ngx_md5_final(digest, &md5);

    md5_hex.len = 32;
    md5_hex.data = ngx_pnalloc(r->pool, md5_hex.len);
    if (md5_hex.data == NULL) {
        md5_hex.len = 0;
        return md5_hex;
    }

    ngx_hex_dump(md5_hex.data, digest, 16);

    return md5_hex;
}


#if (NGX_HTTP_PROXY_FILTER)

static ngx_int_t
ngx_http_proxy_auth_internal_request_filter(ngx_http_request_t *r,
    ngx_http_proxy_filter_ctx_t *ctx)
{
    ngx_int_t                                  rc;
    ngx_str_t                                  fingerprint;
    ngx_http_proxy_auth_internal_loc_conf_t   *plcf;

    if (ctx->headers == NULL) {
        return NGX_DECLINED;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_auth_internal_module);

    if (!plcf->enable) {
        return NGX_DECLINED;
    }

    rc = ngx_http_proxy_auth_internal_build_fingerprint(r, &fingerprint);
    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_http_proxy_auth_internal_set_header(r, ctx->headers,
                                                 &plcf->header_name,
                                                 &fingerprint);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_proxy_auth_internal_set_header(ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *key, ngx_str_t *value)
{
    ngx_uint_t        i;
    ngx_uint_t        hash;
    ngx_uint_t        matched;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    matched = 0;
    hash = ngx_hash_key_lc(key->data, key->len);

    part = &headers->part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len != key->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, key->data, key->len) != 0) {
            continue;
        }

        if (matched) {
            h[i].hash = 0;
            h[i].value.len = 0;
            h[i].next = NULL;
            continue;
        }

        h[i].hash = hash;
        h[i].key = *key;
        h[i].value = *value;
        matched = 1;
    }

    if (matched) {
        return NGX_OK;
    }

    h = ngx_list_push(headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(h, sizeof(ngx_table_elt_t));

    h->hash = hash;
    h->key = *key;
    h->value = *value;

    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        h->hash = 0;
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    h->next = NULL;

    return NGX_OK;
}

#endif


static void *
ngx_http_proxy_auth_internal_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_auth_internal_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_proxy_auth_internal_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_proxy_auth_internal_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_proxy_auth_internal_loc_conf_t  *prev = parent;
    ngx_http_proxy_auth_internal_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->secret, prev->secret, "");
    ngx_conf_merge_str_value(conf->header_name, prev->header_name,
                             "X-Fingerprint");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_proxy_auth_internal_init(ngx_conf_t *cf)
{
#if (NGX_HTTP_PROXY_FILTER)
    ngx_http_proxy_filter_pt          *h;
    ngx_http_proxy_filter_main_conf_t *pmcf;

    pmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_proxy_filter_module);
    if (pmcf == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(&pmcf->phases[NGX_HTTP_PROXY_REQUEST_FILTER]);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_proxy_auth_internal_request_filter;
#endif

    return NGX_OK;
}
