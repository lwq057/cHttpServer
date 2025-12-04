#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <httpserver.h>

static http_server_t* g_server_current = NULL;
static http_req_t* g_req_current = NULL;
static http_res_t* g_res_current = NULL;

#define MAX_METHOD_LEN 16
#define MAX_VERSION_LEN 16

typedef struct route_seg {
    enum { SEG_LITERAL, SEG_PARAM, SEG_WILDCARD } type;
    char* text;
    size_t text_len;
} route_seg;

typedef struct route_entry {
    unsigned method_mask;
    route_seg* segs;
    size_t seg_count;
    http_handler_t handler;
    struct route_entry* next;
} route_entry;

typedef struct route_bucket { char* key; route_entry* head; } route_bucket;

typedef struct {
    char* url;
    char* path;
    char* query;
} url_parts;

typedef enum {
    BODY_NONE,
    BODY_LENGTH,
    BODY_CHUNKED
} body_mode_t;

static inline int httpServer_listen_noctx(int port, const char* ip) { return httpServer_listen(g_server_current, port, ip); }
static inline void httpServer_close_noctx(void) { httpServer_close(g_server_current); }
static inline int httpServer_get_noctx(const char* path, http_handler_t handler) { return httpServer_get(g_server_current, path, handler); }
static inline int httpServer_post_noctx(const char* path, http_handler_t handler) { return httpServer_post(g_server_current, path, handler); }
static inline int httpServer_any_noctx(const char* path, http_handler_t handler) { return httpServer_any(g_server_current, path, handler); }
static inline int httpServer_put_noctx(const char* path, http_handler_t handler) { return httpServer_put(g_server_current, path, handler); }
static inline int httpServer_delete_noctx(const char* path, http_handler_t handler) { return httpServer_delete(g_server_current, path, handler); }
static inline int httpServer_patch_noctx(const char* path, http_handler_t handler) { return httpServer_patch(g_server_current, path, handler); }
static inline int httpServer_head_noctx(const char* path, http_handler_t handler) { return httpServer_head(g_server_current, path, handler); }
static inline int httpServer_options_noctx(const char* path, http_handler_t handler) { return httpServer_options(g_server_current, path, handler); }

static inline void res_writeStatus_noctx(int code, const char* phrase) { if (g_res_current) res_writeStatus(g_res_current, code, phrase); }
static inline void res_writeHeader_noctx(const char* key, const char* value) { if (g_res_current) res_writeHeader(g_res_current, key, value); }
static inline void res_write_noctx(const unsigned char* chunk, size_t len) { if (g_res_current) res_write(g_res_current, chunk, len); }
static inline void res_writeRaw_noctx(const unsigned char* chunk, size_t len) { if (g_res_current) res_writeRaw(g_res_current, chunk, len); }
static inline void res_end_noctx(const unsigned char* chunk, size_t len) { if (g_res_current) res_end(g_res_current, chunk, len); }
static inline void res_close_noctx(void) { if (g_res_current) res_close(g_res_current); }
static inline void res_cork_start_noctx(void) { if (g_res_current) res_cork_start(g_res_current); }
static inline void res_cork_end_noctx(void) { if (g_res_current) res_cork_end(g_res_current); }
static inline void res_cork_noctx(http_cork_cb cb) { if (g_res_current) res_cork(g_res_current, cb); }
static inline int res_removeHeader_noctx(const char* key) { return g_res_current ? res_removeHeader(g_res_current, key) : 0; }

static inline const char* req_getHeader_noctx(const char* key) { return g_req_current ? req_getHeader(g_req_current, key) : NULL; }
static inline const char* req_getQuery_noctx(const char* key) { return g_req_current ? req_getQuery(g_req_current, key) : NULL; }
static inline const char* req_getParameter_noctx(const char* key) { return g_req_current ? req_getParameter(g_req_current, key) : NULL; }
static inline void req_onData_noctx(http_ondata_cb cb) { if (g_req_current) req_onData(g_req_current, cb); }
static inline void req_onAborted_noctx(http_onaborted_cb cb) { if (g_req_current) req_onAborted(g_req_current, cb); }
static inline void req_close_noctx(void) { if (g_req_current) req_close(g_req_current); }
static inline void req_end_noctx(void) { if (g_req_current) req_end(g_req_current); }
static inline void req_pause_noctx(void) { if (g_req_current) req_pause(g_req_current); }
static inline void req_resume_noctx(void) { if (g_req_current) req_resume(g_req_current); }
static inline http_res_t* req_getResponse_noctx(void) { return g_req_current ? req_getResponse(g_req_current) : NULL; }

static void params_init(param_list* pl) { pl->items=NULL; pl->count=pl->cap=0; }
static void params_free(param_list* pl){ for(size_t i=0;i<pl->count;i++){free(pl->items[i].key);free(pl->items[i].val);} free(pl->items); pl->items=NULL; pl->count=pl->cap=0; }
static void params_set(param_list* pl, const char* k, const char* v){ if(pl->count==pl->cap){ size_t nc=pl->cap?pl->cap*2:8; pl->items=(param_kv*)realloc(pl->items,nc*sizeof(param_kv)); pl->cap=nc;} pl->items[pl->count].key=strdup(k); pl->items[pl->count].val=strdup(v); pl->count++; }
static const char* params_get(param_list* pl, const char* k){ for(size_t i=0;i<pl->count;i++){ if(strcmp(pl->items[i].key,k)==0) return pl->items[i].val; } return NULL; }

typedef struct http_conn {
    uv_tcp_t handle;
    uv_loop_t* loop;
    struct http_server* server;
    int closed;

    char method[MAX_METHOD_LEN];
    char version[MAX_VERSION_LEN];
    url_parts urlp;
    header_list headers;
    size_t header_bytes;
    size_t content_length;
    body_mode_t body_mode;
    size_t body_read;
    int header_done;
    int response_started;
    int request_served;

    http_ondata_cb onBody;
    http_onaborted_cb onaborted;
    int paused;

    uv_timer_t ka_timer;

    char* readbuf;
    size_t readbuf_size;
    size_t readbuf_used;
    char* raw_header;
    param_list params;
    http_req_t* current_req;
    http_res_t* current_res;
    unsigned long long tryWriteHistory;
    unsigned short tryWriteCount;
    unsigned short tryWriteWindow;
    unsigned method_mask;
} http_conn;


static void header_list_init(header_list* hl) {
    hl->items = NULL;
    hl->count = 0;
    hl->cap = 0;
}

static void header_list_free(header_list* hl) {
    for (size_t i = 0; i < hl->count; i++) {
        free(hl->items[i].key);
        free(hl->items[i].value);
    }
    free(hl->items);
    hl->items = NULL;
    hl->count = hl->cap = 0;
}

static char* lower_dup(const char* s) {
    size_t n = strlen(s);
    char* o = (char*)malloc(n + 1);
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        o[i] = c;
    }
    o[n] = '\0';
    return o;
}

static char* lower_dup_n(const char* s, size_t n) {
    char* o = (char*)malloc(n + 1);
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        o[i] = c;
    }
    o[n] = '\0';
    return o;
}

static void header_list_set(header_list* hl, const char* key, const char* value) {
    char* lk = lower_dup(key);
    for (size_t i = 0; i < hl->count; i++) {
        if (strcmp(hl->items[i].key, lk) == 0) {
            free(hl->items[i].value);
            hl->items[i].value = strdup(value);
            free(lk);
            return;
        }
    }
    if (hl->count == hl->cap) {
        size_t ncap = hl->cap ? hl->cap * 2 : 8;
        hl->items = (header_kv*)realloc(hl->items, ncap * sizeof(header_kv));
        hl->cap = ncap;
    }
    hl->items[hl->count].key = lk;
    hl->items[hl->count].value = strdup(value);
    hl->count++;
}

static void header_list_setn(header_list* hl, const char* key, size_t klen, const char* value, size_t vlen) {
    char* lk = lower_dup_n(key, klen);
    for (size_t i = 0; i < hl->count; i++) {
        if (strcmp(hl->items[i].key, lk) == 0) {
            free(hl->items[i].value);
            hl->items[i].value = (char*)malloc(vlen + 1);
            memcpy(hl->items[i].value, value, vlen);
            hl->items[i].value[vlen] = '\0';
            free(lk);
            return;
        }
    }
    if (hl->count == hl->cap) {
        size_t ncap = hl->cap ? hl->cap * 2 : 8;
        hl->items = (header_kv*)realloc(hl->items, ncap * sizeof(header_kv));
        hl->cap = ncap;
    }
    hl->items[hl->count].key = lk;
    hl->items[hl->count].value = (char*)malloc(vlen + 1);
    memcpy(hl->items[hl->count].value, value, vlen);
    hl->items[hl->count].value[vlen] = '\0';
    hl->count++;
}

static const char* header_list_get(header_list* hl, const char* key) {
    char* lk = lower_dup(key);
    for (size_t i = 0; i < hl->count; i++) {
        if (strcmp(hl->items[i].key, lk) == 0) { free(lk); return hl->items[i].value; }
    }
    free(lk);
    return NULL;
}
static int header_list_remove(header_list* hl, const char* key) {
    char* lk = lower_dup(key);
    for (size_t i = 0; i < hl->count; i++) {
        if (strcmp(hl->items[i].key, lk) == 0) {
            free(hl->items[i].key);
            free(hl->items[i].value);
            for (size_t j = i + 1; j < hl->count; j++) hl->items[j-1] = hl->items[j];
            hl->count--;
            free(lk);
            return 1;
        }
    }
    free(lk);
    return 0;
}

static const char STR_HTTP11[] = "HTTP/1.1 ";
static const char STR_SP[] = " ";
static const char STR_COLON_SP[] = ": ";
static const char STR_CRLF[] = "\r\n";
static const char STR_CHUNKED[] = "chunked";

static void free_ptr_array(void* p) {
    if (!p) return;
    char** arr = (char**)p;
    size_t i = 0; while (arr[i]) { free(arr[i]); i++; }
    free(arr);
}

static void cork_reset(http_res_t* res) {
    res->cork_manual = 0; res->cork_scoped = 0;
    if (res->cork_bufs) { free(res->cork_bufs); res->cork_bufs = NULL; }
    if (res->cork_dyn_ptrs) { free(res->cork_dyn_ptrs); res->cork_dyn_ptrs = NULL; }
    res->cork_count = res->cork_cap = 0;
    res->cork_dyn_count = res->cork_dyn_cap = 0;
    res->cork_bytes = 0; res->cork_limit = 64 * 1024;
}

static void cork_ensure_bufs(http_res_t* res, int need) {
    if (res->cork_count + need > res->cork_cap) {
        int nc = res->cork_cap ? res->cork_cap * 2 : 32;
        while (res->cork_count + need > nc) nc *= 2;
        res->cork_bufs = realloc(res->cork_bufs, sizeof(uv_buf_t) * nc);
        res->cork_cap = nc;
    }
}

static void cork_ensure_ptrs(http_res_t* res, int need) {
    if (res->cork_dyn_count + need + 1 > res->cork_dyn_cap) {
        int nc = res->cork_dyn_cap ? res->cork_dyn_cap * 2 : 16;
        while (res->cork_dyn_count + need + 1 > nc) nc *= 2;
        res->cork_dyn_ptrs = (char**)realloc(res->cork_dyn_ptrs, sizeof(char*) * nc);
        res->cork_dyn_cap = nc;
    }
}

static void cork_append(http_res_t* res, uv_buf_t* bufs, int n, char** dyn_ptrs, int dyn_n) {
    cork_ensure_bufs(res, n);
    for (int i = 0; i < n; i++) { ((uv_buf_t*)res->cork_bufs)[res->cork_count++] = bufs[i]; res->cork_bytes += bufs[i].len; }
    if (dyn_n > 0) {
        cork_ensure_ptrs(res, dyn_n);
        for (int i = 0; i < dyn_n; i++) res->cork_dyn_ptrs[res->cork_dyn_count++] = dyn_ptrs[i];
    }
}

void adaptiveWriteVec(http_conn* c, const uv_buf_t* bufs, int n, void* aux, void (*aux_free)(void*));

static void cork_flush(http_res_t* res) {
    if (res->cork_count == 0) return;
    if (res->cork_dyn_ptrs) {
        cork_ensure_ptrs(res, 0);
        res->cork_dyn_ptrs[res->cork_dyn_count] = NULL;
    }
    adaptiveWriteVec(res->conn, (uv_buf_t*)res->cork_bufs, res->cork_count, res->cork_dyn_ptrs, free_ptr_array);
    free(res->cork_bufs); res->cork_bufs = NULL; res->cork_count = res->cork_cap = 0;
    res->cork_dyn_ptrs = NULL; res->cork_dyn_count = res->cork_dyn_cap = 0;
    res->cork_bytes = 0;
}

static void on_conn_closed(uv_handle_t* h);
static void on_server_closed(uv_handle_t* h) { free(h); }

static void response_finalize(http_res_t* res) {
    http_conn* c = res->conn;
    res->ended = 1;
    res->writePhase = 1;
    c->request_served++;
    if (!c->server->opt.keep_alive || (c->server->opt.keep_alive_requests && (size_t)c->request_served >= c->server->opt.keep_alive_requests)) {
        uv_close((uv_handle_t*)&c->handle, on_conn_closed);
        c->closed = 1;
    } else {
        c->header_done = 0;
        c->headers.count = 0;
        c->header_bytes = 0;
        c->readbuf_used = 0;
        c->body_read = 0;
        c->response_started = 0;
        header_list_free(&res->header);
        res->headers_locked = 0;
        res->chunked = 0;
        res->ended = 0;
        cork_reset(res);
        if (c->raw_header) { free(c->raw_header); c->raw_header = NULL; }
        if (c->current_req) { if (c->current_req->query_tmp) free(c->current_req->query_tmp); free(c->current_req->remoteAddress); }
        free(c->current_req); c->current_req = NULL;
        free(c->current_res); c->current_res = NULL;
        c->onBody = NULL;
    }
}

static void res_send_or_cork(http_res_t* res, uv_buf_t* bufs, int n, char** dyn_ptrs, int dyn_n) {
    if ((res->cork_manual || res->cork_scoped)) {
        cork_append(res, bufs, n, dyn_ptrs, dyn_n);
        if (res->cork_bytes >= res->cork_limit) cork_flush(res);
    } else {
        char** aux = NULL;
        if (dyn_n > 0) {
            aux = (char**)malloc(sizeof(char*) * (dyn_n + 1));
            for (int i = 0; i < dyn_n; i++) aux[i] = dyn_ptrs[i];
            aux[dyn_n] = NULL;
        }
        adaptiveWriteVec(res->conn, bufs, n, aux, aux ? free_ptr_array : NULL);
    }
}

static char* str_dup_range(const char* s, size_t len) {
    char* out = (char*)malloc(len + 1);
    memcpy(out, s, len);
    out[len] = '\0';
    return out;
}

static void split_url(const char* url, url_parts* out) {
    const char* q = strchr(url, '?');
    if (q) {
        out->path = str_dup_range(url, (size_t)(q - url));
        out->query = strdup(q + 1);
    } else {
        out->path = strdup(url);
        out->query = strdup("");
    }
    out->url = strdup(url);
}

static void url_parts_free(url_parts* u) {
    free(u->url);
    free(u->path);
    free(u->query);
    u->url = u->path = u->query = NULL;
}

static void free_route(route_entry* r) {
    for (size_t i = 0; i < r->seg_count; i++) free(r->segs[i].text);
    free(r->segs);
}

static struct route_bucket* find_bucket(struct http_server* s, const char* key) {
    for (size_t i = 0; i < s->bucket_len; i++) {
        if (strcmp(s->buckets[i].key, key) == 0) return &s->buckets[i];
    }
    return NULL;
}

static struct route_bucket* ensure_bucket(struct http_server* s, const char* key) {
    struct route_bucket* b = find_bucket(s, key);
    if (b) return b;
    if (s->bucket_len == s->bucket_cap) {
        size_t nc = s->bucket_cap ? s->bucket_cap * 2 : 8;
        s->buckets = (struct route_bucket*)realloc(s->buckets, nc * sizeof(*s->buckets));
        s->bucket_cap = nc;
    }
    s->buckets[s->bucket_len].key = strdup(key);
    s->buckets[s->bucket_len].head = NULL;
    return &s->buckets[s->bucket_len++];
}

static int parse_route_pattern(const char* pattern, route_seg** out_segs, size_t* out_count) {
    size_t count = 0, cap = 0;
    route_seg* segs = NULL;
    const char* p = pattern;
    while (*p) {
        while (*p == '/') p++;
        const char* end = strchr(p, '/');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == 0) { if (!end) break; p = end + 1; continue; }
        route_seg seg;
        if (len == 1 && *p == '*') {
            seg.type = SEG_WILDCARD;
            seg.text = strdup("*");
            seg.text_len = 1;
        } else if (*p == ':') {
            seg.type = SEG_PARAM;
            seg.text = str_dup_range(p + 1, len - 1);
            seg.text_len = len - 1;
        } else {
            seg.type = SEG_LITERAL;
            seg.text = str_dup_range(p, len);
            seg.text_len = len;
        }
        if (count == cap) {
            size_t ncap = cap ? cap * 2 : 8;
            segs = (route_seg*)realloc(segs, ncap * sizeof(route_seg));
            cap = ncap;
        }
        segs[count++] = seg;
        p = end ? end + 1 : p + len;
    }
    *out_segs = segs;
    *out_count = count;
    return 0;
}

static int match_route(const route_entry* r, const char* path, param_list* out_params) {
    params_init(out_params);
    size_t idx = 0; size_t start = 0; size_t len = strlen(path);
    for (size_t i = 0; i < r->seg_count; i++) {
        if (idx > len) { params_free(out_params); return 0; }
        const route_seg* seg = &r->segs[i];
        if (seg->type == SEG_WILDCARD) { return 1; }
        const char* next_slash = strchr(path + start, '/');
        size_t end = next_slash ? (size_t)(next_slash - path) : len;
        size_t comp_len = end - start;
        if (seg->type == SEG_LITERAL) {
            if (comp_len != seg->text_len || strncmp(path + start, seg->text, comp_len) != 0) { params_free(out_params); return 0; }
        } else if (seg->type == SEG_PARAM) {
            char* v = str_dup_range(path + start, comp_len);
            params_set(out_params, seg->text, v);
            free(v);
        }
        start = next_slash ? end + 1 : end;
    }
    if (start != len) { params_free(out_params); return 0; }
    return 1;
}

static unsigned method_to_mask(const char* method) {
    if (strcmp(method, "GET") == 0) return 1<<0;
    if (strcmp(method, "POST") == 0) return 1<<1;
    if (strcmp(method, "PUT") == 0) return 1<<2;
    if (strcmp(method, "DELETE") == 0) return 1<<3;
    if (strcmp(method, "PATCH") == 0) return 1<<4;
    if (strcmp(method, "HEAD") == 0) return 1<<5;
    if (strcmp(method, "OPTIONS") == 0) return 1<<6;
    return 0;
}

typedef struct write_ctx {
    void* aux;
    uv_buf_t* bufs;
    int nbufs;
    void (*aux_free)(void*);
} write_ctx;

static void on_write_done(uv_write_t* req, int status) {
    (void)status;
    write_ctx* ctx = (write_ctx*)req->data;
    if (ctx) {
        if (ctx->bufs) free(ctx->bufs);
        if (ctx->aux && ctx->aux_free) ctx->aux_free(ctx->aux);
        free(ctx);
    }
    free(req);
}

static unsigned long long tryWriteMask(unsigned short n) { return n >= 64 ? ~0ULL : ((1ULL << n) - 1ULL); }

static int tryWriteShouldAttempt(http_conn* c) {
    unsigned short n = c->tryWriteWindow ? c->tryWriteWindow : 10;
    unsigned long long mask = tryWriteMask(n);
    if (c->tryWriteCount < n) return 1;
    return (c->tryWriteHistory & mask) == mask;
}

static void tryWriteRecord(http_conn* c, int full_success) {
    unsigned short n = c->tryWriteWindow ? c->tryWriteWindow : 10;
    unsigned long long mask = tryWriteMask(n);
    c->tryWriteHistory = ((c->tryWriteHistory << 1) | (full_success ? 1ULL : 0ULL)) & mask;
    if (c->tryWriteCount < n) c->tryWriteCount++;
}

static size_t bufs_total_len(const uv_buf_t* bufs, int n) {
    size_t t = 0; for (int i = 0; i < n; i++) t += bufs[i].len; return t;
}

void adaptiveWriteVec(http_conn* c, const uv_buf_t* bufs, int n, void* aux, void (*aux_free)(void*)) {
    size_t total = bufs_total_len(bufs, n);
    if (total == 0) { if (aux && aux_free) aux_free(aux); return; }
    if (tryWriteShouldAttempt(c)) {
        int tw = uv_try_write((uv_stream_t*)&c->handle, (uv_buf_t*)bufs, n);
        int full = (tw == (int)total);
        tryWriteRecord(c, full);
        size_t consumed = (tw > 0) ? (size_t)tw : 0;
        if (full) { if (aux && aux_free) aux_free(aux); return; }
        uv_buf_t* rem = (uv_buf_t*)malloc(sizeof(uv_buf_t) * n);
        int j = 0; size_t skip = consumed;
        for (int i = 0; i < n; i++) {
            if (skip >= bufs[i].len) { skip -= bufs[i].len; continue; }
            char* base = bufs[i].base + skip;
            unsigned l = (unsigned)(bufs[i].len - skip);
            rem[j++] = uv_buf_init(base, l);
            skip = 0;
        }
        write_ctx* ctx = (write_ctx*)malloc(sizeof(write_ctx)); ctx->aux = aux; ctx->bufs = rem; ctx->nbufs = j; ctx->aux_free = aux_free;
        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t)); req->data = ctx;
        uv_write(req, (uv_stream_t*)&c->handle, rem, j, on_write_done);
    } else {
        tryWriteRecord(c, 0);
        uv_buf_t* copy = (uv_buf_t*)malloc(sizeof(uv_buf_t) * n);
        for (int i = 0; i < n; i++) copy[i] = bufs[i];
        write_ctx* ctx = (write_ctx*)malloc(sizeof(write_ctx)); ctx->aux = aux; ctx->bufs = copy; ctx->nbufs = n; ctx->aux_free = aux_free;
        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t)); req->data = ctx;
        uv_write(req, (uv_stream_t*)&c->handle, copy, n, on_write_done);
    }
}

static void res_write_internal(http_res_t* res, const unsigned char* data, size_t len, int final_chunk) {
    if (res->ended) return;
    http_conn* c = res->conn;
    if (!res->headers_locked) {
        res->headers_locked = 1;
        res->writePhase = 0;
        c->response_started = 1;
        header_list_set(&res->header, "connection", c->server->opt.keep_alive ? "keep-alive" : "close");
        int code = res->status_code ? res->status_code : 200;
        const char* phrase = res->status_phrase ? res->status_phrase : "OK";
        if (final_chunk && !res->chunked) {
            char codebuf[16]; int cbl = snprintf(codebuf, sizeof(codebuf), "%d", code);
            size_t phrase_len = strlen(phrase);
            size_t status_len = strlen(STR_HTTP11) + (size_t)cbl + 1 + phrase_len + 2;
            size_t headers_len = 0;
            for (size_t i = 0; i < res->header.count; i++) headers_len += strlen(res->header.items[i].key) + 2 + strlen(res->header.items[i].value) + 2;
            char lenbuf[32]; int lbl = snprintf(lenbuf, sizeof(lenbuf), "%zu", len);
            const char* cl = "Content-Length: "; size_t cllen = strlen(cl);
            size_t total_hdr = status_len + headers_len + cllen + (size_t)lbl + 4;
            if (len == 0) {
                char* header = (char*)malloc(total_hdr);
                size_t off = 0;
                memcpy(header+off, STR_HTTP11, strlen(STR_HTTP11)); off += strlen(STR_HTTP11);
                memcpy(header+off, codebuf, (size_t)cbl); off += (size_t)cbl;
                header[off++] = ' ';
                memcpy(header+off, phrase, phrase_len); off += phrase_len;
                memcpy(header+off, STR_CRLF, 2); off += 2;
                for (size_t i = 0; i < res->header.count; i++) {
                    size_t klen = strlen(res->header.items[i].key);
                    size_t vlen = strlen(res->header.items[i].value);
                    memcpy(header+off, res->header.items[i].key, klen); off += klen;
                    memcpy(header+off, STR_COLON_SP, 2); off += 2;
                    memcpy(header+off, res->header.items[i].value, vlen); off += vlen;
                    memcpy(header+off, STR_CRLF, 2); off += 2;
                }
                memcpy(header+off, cl, cllen); off += cllen;
                memcpy(header+off, lenbuf, (size_t)lbl); off += (size_t)lbl;
                memcpy(header+off, STR_CRLF, 2); off += 2;
                memcpy(header+off, STR_CRLF, 2); off += 2;
                uv_buf_t b = uv_buf_init(header, (unsigned)off);
                res_send_or_cork(res, &b, 1, (char*[]){header}, 1);
            } else {
                size_t total = total_hdr + len;
                char* frame = (char*)malloc(total);
                size_t off = 0;
                memcpy(frame+off, STR_HTTP11, strlen(STR_HTTP11)); off += strlen(STR_HTTP11);
                memcpy(frame+off, codebuf, (size_t)cbl); off += (size_t)cbl;
                frame[off++] = ' ';
                memcpy(frame+off, phrase, phrase_len); off += phrase_len;
                memcpy(frame+off, STR_CRLF, 2); off += 2;
                for (size_t i = 0; i < res->header.count; i++) {
                    size_t klen = strlen(res->header.items[i].key);
                    size_t vlen = strlen(res->header.items[i].value);
                    memcpy(frame+off, res->header.items[i].key, klen); off += klen;
                    memcpy(frame+off, STR_COLON_SP, 2); off += 2;
                    memcpy(frame+off, res->header.items[i].value, vlen); off += vlen;
                    memcpy(frame+off, STR_CRLF, 2); off += 2;
                }
                memcpy(frame+off, cl, cllen); off += cllen;
                memcpy(frame+off, lenbuf, (size_t)lbl); off += (size_t)lbl;
                memcpy(frame+off, STR_CRLF, 2); off += 2;
                memcpy(frame+off, STR_CRLF, 2); off += 2;
                memcpy(frame+off, data, len); off += len;
                uv_buf_t fb = uv_buf_init(frame, (unsigned)off);
                res_send_or_cork(res, &fb, 1, (char*[]){frame}, 1);
            }
        } else {
            if (len > 0 && !final_chunk) { res->chunked = 1; header_list_set(&res->header, "transfer-encoding", STR_CHUNKED); }
            char codebuf[16]; int cbl = snprintf(codebuf, sizeof(codebuf), "%d", code);
            size_t phrase_len = strlen(phrase);
            size_t status_len = strlen(STR_HTTP11) + (size_t)cbl + 1 + phrase_len + 2;
            size_t headers_len = 0; for (size_t i = 0; i < res->header.count; i++) headers_len += strlen(res->header.items[i].key) + 2 + strlen(res->header.items[i].value) + 2;
            size_t extra = 2; // final CRLF
            char lenbuf[32]; int lbl = 0; const char* cl = "Content-Length: "; size_t cllen = strlen(cl);
            if (!res->chunked && final_chunk) { lbl = snprintf(lenbuf, sizeof(lenbuf), "%zu", len); extra += cllen + (size_t)lbl + 2; }
            size_t total_hdr = status_len + headers_len + extra;
            char* hdr = (char*)malloc(total_hdr);
            size_t off = 0;
            memcpy(hdr+off, STR_HTTP11, strlen(STR_HTTP11)); off += strlen(STR_HTTP11);
            memcpy(hdr+off, codebuf, (size_t)cbl); off += (size_t)cbl;
            hdr[off++] = ' ';
            memcpy(hdr+off, phrase, phrase_len); off += phrase_len;
            memcpy(hdr+off, STR_CRLF, 2); off += 2;
            for (size_t i = 0; i < res->header.count; i++) {
                size_t klen = strlen(res->header.items[i].key);
                size_t vlen = strlen(res->header.items[i].value);
                memcpy(hdr+off, res->header.items[i].key, klen); off += klen;
                memcpy(hdr+off, STR_COLON_SP, 2); off += 2;
                memcpy(hdr+off, res->header.items[i].value, vlen); off += vlen;
                memcpy(hdr+off, STR_CRLF, 2); off += 2;
            }
            if (!res->chunked && final_chunk) { memcpy(hdr+off, cl, cllen); off += cllen; memcpy(hdr+off, lenbuf, (size_t)lbl); off += (size_t)lbl; memcpy(hdr+off, STR_CRLF, 2); off += 2; }
            memcpy(hdr+off, STR_CRLF, 2); off += 2;
            uv_buf_t hb = uv_buf_init(hdr, (unsigned)off);
            res_send_or_cork(res, &hb, 1, (char*[]){hdr}, 1);
        }
    }
    if (len > 0 || (final_chunk && res->chunked)) {
        if (res->chunked) {
            char hdrtmp[32]; int hn = snprintf(hdrtmp, sizeof(hdrtmp), "%zx\r\n", len);
            size_t total = (size_t)hn + len + 2;
            char* payload = (char*)malloc(total);
            memcpy(payload, hdrtmp, hn);
            if (len > 0) memcpy(payload + hn, data, len);
            memcpy(payload + hn + len, "\r\n", 2);
            uv_buf_t pb = uv_buf_init(payload, (unsigned)total);
            res_send_or_cork(res, &pb, 1, (char*[]){payload}, 1);
            if (final_chunk) {
                char* endp = (char*)malloc(5); memcpy(endp, "0\r\n\r\n", 5);
                uv_buf_t eb = uv_buf_init(endp, 5);
                res_send_or_cork(res, &eb, 1, (char*[]){endp}, 1);
            }
        } else if (!final_chunk && len > 0) {
            char* payload = (char*)malloc(len);
            memcpy(payload, data, len);
            uv_buf_t b = uv_buf_init(payload, (unsigned)len);
            res_send_or_cork(res, &b, 1, (char*[]){payload}, 1);
        }
    }
    if (final_chunk) {
        if (res->cork_manual || res->cork_scoped) {
            res->ended = 1;
        } else {
            response_finalize(res);
        }
    }
}

static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    http_conn* c = (http_conn*)handle->data;
    if (c->readbuf_size < suggested_size) {
        c->readbuf_size = suggested_size;
        c->readbuf = (char*)realloc(c->readbuf, c->readbuf_size);
    }
    *buf = uv_buf_init(c->readbuf, (unsigned)c->readbuf_size);
}

static const char* trim(const char* s, size_t* out_len) {
    size_t len = *out_len;
    size_t i = 0; while (i < len && (s[i] == ' ' || s[i] == '\t')) i++;
    size_t j = len; while (j > i && (s[j-1] == ' ' || s[j-1] == '\t')) j--;
    *out_len = j - i; return s + i;
}

static void parse_headers(http_conn* c, const char* data, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        const char* line_end = (const char*)memchr(data + pos, '\n', len - pos);
        if (!line_end) break;
        size_t line_len = (size_t)(line_end - (data + pos));
        if (line_len && data[pos + line_len - 1] == '\r') line_len--;
        if (line_len == 0) { c->header_done = 1; return; }
        const char* colon = (const char*)memchr(data + pos, ':', line_len);
        if (colon) {
            size_t klen = (size_t)(colon - (data + pos)); size_t vlen = line_len - klen - 1;
            const char* k = trim(data + pos, &klen);
            const char* v = trim(colon + 1, &vlen);
            header_list_setn(&c->headers, k, klen, v, vlen);
        }
        size_t consumed = (size_t)(line_end - (data + pos)) + 1;
        pos += consumed;
        c->header_bytes += consumed;
        if (c->server->opt.max_header_size && c->header_bytes > c->server->opt.max_header_size) {
            uv_close((uv_handle_t*)&c->handle, NULL);
            c->closed = 1; return;
        }
    }
}

static int parse_request_line(http_conn* c, const char* data, size_t len) {
    const char* sp1 = (const char*)memchr(data, ' ', len);
    if (!sp1) return -1;
    const char* sp2 = (const char*)memchr(sp1 + 1, ' ', len - (sp1 - data) - 1);
    if (!sp2) return -1;
    size_t mlen = (size_t)(sp1 - data);
    size_t url_len = (size_t)(sp2 - sp1 - 1);
    size_t vlen = len - (size_t)(sp2 - data) - 1;
    if (mlen >= MAX_METHOD_LEN || vlen >= MAX_VERSION_LEN) return -1;
    memcpy(c->method, data, mlen); c->method[mlen] = '\0';
    char* url = str_dup_range(sp1 + 1, url_len);
    split_url(url, &c->urlp);
    free(url);
    memcpy(c->version, sp2 + 1, vlen); c->version[vlen] = '\0';
    c->method_mask = method_to_mask(c->method);
    return 0;
}

static char* compute_remote_address(http_conn* c) {
    char buf[64]; buf[0] = '\0'; struct sockaddr_storage ss; int len = sizeof(ss);
    if (uv_tcp_getpeername(&c->handle, (struct sockaddr*)&ss, &len) == 0) {
        if (ss.ss_family == AF_INET) { struct sockaddr_in* a = (struct sockaddr_in*)&ss; uv_ip4_name(a, buf, sizeof(buf)); }
        else if (ss.ss_family == AF_INET6) { struct sockaddr_in6* a6 = (struct sockaddr_in6*)&ss; uv_ip6_name(a6, buf, sizeof(buf)); }
    }
    size_t n = strlen(buf); char* out = (char*)malloc(n + 1); memcpy(out, buf, n + 1); return out;
}

static void req_init_from_conn(http_req_t* req, http_conn* c) {
    req->conn = c;
    req->url = c->urlp.url;
    req->path = c->urlp.path;
    req->query = c->urlp.query;
    req->rawHeader = c->raw_header;
    req->remoteAddress = compute_remote_address(c);
    req->method = c->method;
    req->aborted = c->closed;
    req->header = (const header_list*)&c->headers;
    req->parameter = (const param_list*)&c->params;
    req->query_tmp = NULL;
    req->getHeader = req_getHeader_noctx;
    req->getQuery = req_getQuery_noctx;
    req->getParameter = req_getParameter_noctx;
    req->onData = req_onData_noctx;
    req->onAborted = req_onAborted_noctx;
    req->close = req_close_noctx;
    req->end = req_end_noctx;
    req->pause = req_pause_noctx;
    req->resume = req_resume_noctx;
    req->getResponse = req_getResponse_noctx;
}
static void res_init_from_conn(http_res_t* res, http_conn* c) {
    res->conn = c;
    res->status_code = 0;
    res->status_phrase = NULL;
    header_list_init(&res->header);
    res->headers_locked = 0;
    res->chunked = 0;
    res->ended = 0;
    res->cork_manual = 0;
    res->cork_scoped = 0;
    res->cork_bufs = NULL;
    res->cork_count = 0;
    res->cork_cap = 0;
    res->cork_dyn_ptrs = NULL;
    res->cork_dyn_count = 0;
    res->cork_dyn_cap = 0;
    res->cork_bytes = 0;
    res->cork_limit = 64 * 1024;
    res->writeStatus = res_writeStatus_noctx;
    res->writeHeader = res_writeHeader_noctx;
    res->removeHeader = res_removeHeader_noctx;
    res->write = res_write_noctx;
    res->writeRaw = res_writeRaw_noctx;
    res->end = res_end_noctx;
    res->close = res_close_noctx;
    res->cork_start = res_cork_start_noctx;
    res->cork_end = res_cork_end_noctx;
    res->cork = res_cork_noctx;
    res->writePhase = -1;
}

static void dispatch_request(http_conn* c) {
    http_server_t* s = c->server;
    route_entry* r = s->routes;
    http_handler_t handler = NULL;
    param_list matched_params; params_init(&matched_params);
    const char* path = c->urlp.path[0]=='/'?c->urlp.path+1:c->urlp.path;
    const char* slash = strchr(path, '/');
    size_t first_len = slash ? (size_t)(slash - path) : strlen(path);
    char* first = str_dup_range(path, first_len);
    struct route_bucket* b = (first_len > 0) ? find_bucket(s, first) : NULL;
    if (b) {
        r = b->head;
        while (r) {
            param_list tmp; if (match_route(r, path, &tmp)) {
                unsigned mm = c->method_mask;
                if (r->method_mask == 0 || (r->method_mask & mm)) { handler = r->handler; params_free(&matched_params); matched_params = tmp; break; }
                params_free(&tmp);
            }
            r = r->next;
        }
    }
    free(first);
    if (!handler) {
        r = s->routes;
        while (r) {
            param_list tmp; if (match_route(r, path, &tmp)) {
                unsigned mm = c->method_mask;
                if (r->method_mask == 0 || (r->method_mask & mm)) { handler = r->handler; params_free(&matched_params); matched_params = tmp; break; }
                params_free(&tmp);
            }
            r = r->next;
        }
    }
    params_free(&c->params);
    c->params = matched_params;
    http_req_t* req = (http_req_t*)malloc(sizeof(http_req_t));
    http_res_t* res = (http_res_t*)malloc(sizeof(http_res_t));
    req_init_from_conn(req, c); res_init_from_conn(res, c);
    if (handler) {
        c->current_req = req;
        c->current_res = res;
        g_server_current = s; g_req_current = req; g_res_current = res;
        handler(req, res);
    } else {
        res_writeStatus(res, 404, "Not Found");
        const char* body = "Not Found";
        res_end(res, (const unsigned char*)body, strlen(body));
    }
}

static void on_keepalive_timeout(uv_timer_t* t);

static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    http_conn* c = (http_conn*)stream->data;
    if (nread < 0) {
        if (c->onaborted) c->onaborted();
        uv_close((uv_handle_t*)&c->handle, on_conn_closed);
        c->closed = 1; return;
    }
    if (c->paused) return;
    if (c->server->opt.keep_alive && c->server->opt.keep_alive_timeout) {
        uv_timer_stop(&c->ka_timer);
        uv_timer_start(&c->ka_timer, on_keepalive_timeout, c->server->opt.keep_alive_timeout, 0);
    }
    c->readbuf_used += (size_t)nread;
    char* data = c->readbuf;
    size_t len = c->readbuf_used;
    if (!c->header_done) {
        const char* hdr_end = NULL;
        for (size_t i = 0; i + 3 < len; i++) {
            if (data[i]=='\r'&&data[i+1]=='\n'&&data[i+2]=='\r'&&data[i+3]=='\n') { hdr_end = data + i + 4; break; }
        }
        if (!hdr_end) return;
        const char* line_end = (const char*)memchr(data, '\n', len);
        if (!line_end) return;
        size_t rl_len = (size_t)(line_end - data);
        if (rl_len && data[rl_len-1]=='\r') rl_len--;
        if (parse_request_line(c, data, rl_len) != 0) { uv_close((uv_handle_t*)&c->handle, NULL); c->closed=1; return; }
        size_t headers_len = (size_t)(hdr_end - (data + rl_len + 2));
        parse_headers(c, data + rl_len + 2, headers_len);
        if (c->raw_header) { free(c->raw_header); c->raw_header = NULL; }
        c->raw_header = (char*)malloc(headers_len + 1);
        memcpy(c->raw_header, data + rl_len + 2, headers_len);
        c->raw_header[headers_len] = '\0';
        c->header_done = 1;
        const char* cl = header_list_get(&c->headers, "content-length");
        const char* te = header_list_get(&c->headers, "transfer-encoding");
        if (te && strcmp(te, STR_CHUNKED) == 0) c->body_mode = BODY_CHUNKED;
        else if (cl) { c->body_mode = BODY_LENGTH; c->content_length = (size_t)strtoull(cl, NULL, 10); }
        else c->body_mode = BODY_NONE;
        if (c->server->opt.max_body_size && c->body_mode == BODY_LENGTH && c->content_length > c->server->opt.max_body_size) {
            http_req_t* req = (http_req_t*)malloc(sizeof(http_req_t));
            http_res_t* res = (http_res_t*)malloc(sizeof(http_res_t));
            req_init_from_conn(req, c); res_init_from_conn(res, c);
            c->current_req = req; c->current_res = res;
            g_server_current = c->server; g_req_current = req; g_res_current = res;
            res_writeStatus(res, 413, "Payload Too Large");
            const char* body = "Payload Too Large";
            res_end(res, (const unsigned char*)body, strlen(body));
            c->readbuf_used = 0;
            return;
        }
        dispatch_request(c);
        size_t body_avail = len - (size_t)(hdr_end - data);
        {
            size_t body_pos = (size_t)(hdr_end - data);
            if (c->body_mode == BODY_LENGTH) {
                size_t remaining = c->content_length - c->body_read;
                size_t take = body_avail < remaining ? body_avail : remaining;
                if (take > 0) {
                    int last = (c->body_read + take == c->content_length);
                    if (c->onBody && c->current_req && c->current_res) { g_server_current = c->server; g_req_current = c->current_req; g_res_current = c->current_res; c->onBody(c->current_req, c->current_res, (unsigned char*)data + body_pos, take, last); }
                }
                c->body_read += take;
                if (c->server->opt.max_body_size && c->body_read > c->server->opt.max_body_size) {
                    res_writeStatus(c->current_res, 413, "Payload Too Large");
                    const char* body = "Payload Too Large";
                    res_end(c->current_res, (const unsigned char*)body, strlen(body));
                    c->readbuf_used = 0; return;
                }
                if (c->body_read == c->content_length) { c->readbuf_used = 0; return; }
            } else if (c->body_mode == BODY_CHUNKED) {
                size_t pos = body_pos;
                while (pos + 1 < len) {
                    const char* nl = (const char*)memchr(data + pos, '\n', len - pos);
                    if (!nl) break;
                    size_t sl = (size_t)(nl - (data + pos)); if (sl && data[pos+sl-1]=='\r') sl--;
                    char* szbuf = str_dup_range(data + pos, sl);
                    size_t chunk_len = (size_t)strtoull(szbuf, NULL, 16);
                    free(szbuf);
                    pos += sl + 2;
                    if (c->server->opt.max_body_size && c->body_read + chunk_len > c->server->opt.max_body_size) {
                        http_req_t* req = c->current_req ? c->current_req : (http_req_t*)malloc(sizeof(http_req_t));
                        http_res_t* res = c->current_res ? c->current_res : (http_res_t*)malloc(sizeof(http_res_t));
                        if (!c->current_req) { req_init_from_conn(req, c); c->current_req = req; }
                        if (!c->current_res) { res_init_from_conn(res, c); c->current_res = res; }
                        g_server_current = c->server; g_req_current = c->current_req; g_res_current = c->current_res;
                        res_writeStatus(c->current_res, 413, "Payload Too Large");
                        const char* body = "Payload Too Large";
                        res_end(c->current_res, (const unsigned char*)body, strlen(body));
                        c->readbuf_used = 0;
                        return;
                    }
                    if (chunk_len == 0) { if (c->onBody && c->current_req && c->current_res) c->onBody(c->current_req, c->current_res, NULL, 0, 1); c->readbuf_used = 0; return; }
                    if (pos + chunk_len + 2 > len) break;
                    if (c->onBody && c->current_req && c->current_res) { g_server_current = c->server; g_req_current = c->current_req; g_res_current = c->current_res; c->onBody(c->current_req, c->current_res, (unsigned char*)data + pos, chunk_len, 0); }
                    pos += chunk_len + 2;
                }
            }
        }
    } else {
        if (c->body_mode == BODY_LENGTH) {
            size_t remaining = c->content_length - c->body_read;
            size_t take = len < remaining ? len : remaining;
            if (take > 0) {
                int last = (c->body_read + take == c->content_length);
                if (c->onBody && c->current_req && c->current_res) { g_server_current = c->server; g_req_current = c->current_req; g_res_current = c->current_res; c->onBody(c->current_req, c->current_res, (unsigned char*)data, take, last); }
            }
            c->body_read += take;
            if (c->body_read == c->content_length) { c->readbuf_used = 0; }
        } else if (c->body_mode == BODY_CHUNKED) {
            size_t pos = 0;
            while (pos + 1 < len) {
                const char* nl = (const char*)memchr(data + pos, '\n', len - pos);
                if (!nl) break;
                size_t sl = (size_t)(nl - (data + pos)); if (sl && data[pos+sl-1]=='\r') sl--;
                char* szbuf = str_dup_range(data + pos, sl);
                size_t chunk_len = (size_t)strtoull(szbuf, NULL, 16);
                free(szbuf);
                pos += sl + 2;
                if (chunk_len == 0) { if (c->onBody && c->current_req && c->current_res) c->onBody(c->current_req, c->current_res, NULL, 0, 1); c->readbuf_used = 0; return; }
                if (pos + chunk_len + 2 > len) break;
                if (c->onBody && c->current_req && c->current_res) { g_server_current = c->server; g_req_current = c->current_req; g_res_current = c->current_res; c->onBody(c->current_req, c->current_res, (unsigned char*)data + pos, chunk_len, 0); }
                pos += chunk_len + 2;
            }
        }
    }
}

static void on_connection(uv_stream_t* server, int status) {
    if (status < 0) return;
    http_server_t* s = (http_server_t*)server->data;
    http_conn* c = (http_conn*)calloc(1, sizeof(http_conn));
    c->loop = (uv_loop_t*)s->loop; c->server = s; c->closed = 0; header_list_init(&c->headers);
    c->readbuf_size = s->opt.read_buffer_size ? s->opt.read_buffer_size : 8192; c->readbuf = (char*)malloc(c->readbuf_size); c->readbuf_used = 0;
    uv_tcp_init((uv_loop_t*)s->loop, &c->handle);
    c->handle.data = c;
    {
        int backlog = s->opt.listen_backlog > 0 ? s->opt.listen_backlog : 1024;
        unsigned short n = (unsigned short)(backlog / 100);
        if (n < 10) n = 10;
        if (n > 64) n = 64;
        c->tryWriteWindow = n;
        c->tryWriteHistory = 0;
        c->tryWriteCount = 0;
    }
    if (uv_accept(server, (uv_stream_t*)&c->handle) == 0) {
        if (s->opt.max_connections && s->conn_count >= s->opt.max_connections) {
            uv_close((uv_handle_t*)&c->handle, NULL);
            free(c->readbuf);
            header_list_free(&c->headers);
            free(c);
            return;
        }
        s->conn_count++;
        uv_tcp_nodelay(&c->handle, 1);
        uv_tcp_keepalive(&c->handle, 1, 60);
        if (s->opt.keep_alive && s->opt.keep_alive_timeout) { uv_timer_init((uv_loop_t*)s->loop, &c->ka_timer); c->ka_timer.data = c; uv_timer_start(&c->ka_timer, on_keepalive_timeout, s->opt.keep_alive_timeout, 0); }
        uv_read_start((uv_stream_t*)&c->handle, on_alloc, on_read);
    } else {
        uv_close((uv_handle_t*)&c->handle, NULL);
        free(c->readbuf);
        header_list_free(&c->headers);
        free(c);
    }
}

http_server_t* httpServer(const http_server_options_t* opt) {
    http_server_t* s = (http_server_t*)calloc(1, sizeof(http_server_t));
    s->loop = uv_default_loop();
    if (opt) s->opt = *opt; else memset(&s->opt, 0, sizeof(s->opt));
    if (s->opt.worker_processes == 0) {
        size_t cores = (size_t)uv_available_parallelism();
        s->opt.worker_processes = cores ? cores : 1;
    }
    if (s->opt.read_buffer_size == 0) s->opt.read_buffer_size = 8192;
    {
        uv_tcp_t* srv = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
        uv_tcp_init((uv_loop_t*)s->loop, srv);
        srv->data = s;
        s->server = (void*)srv;
    }
    s->buckets = NULL; s->bucket_len = 0; s->bucket_cap = 0;
    s->listen = httpServer_listen_noctx;
    s->close = httpServer_close_noctx;
    s->get = httpServer_get_noctx;
    s->post = httpServer_post_noctx;
    s->any = httpServer_any_noctx;
    s->put = httpServer_put_noctx;
    s->delete = httpServer_delete_noctx;
    s->patch = httpServer_patch_noctx;
    s->head = httpServer_head_noctx;
    s->options = httpServer_options_noctx;
    g_server_current = s;
    return s;
}

int httpServer_listen(http_server_t* s, int port, const char* ip) {
    struct sockaddr_in addr;
    uv_ip4_addr(ip ? ip : "0.0.0.0", port, &addr);
    if (uv_tcp_bind((uv_tcp_t*)s->server, (const struct sockaddr*)&addr, 0) != 0) return -1;
    uv_tcp_simultaneous_accepts((uv_tcp_t*)s->server, 1);
    int backlog = s->opt.listen_backlog > 0 ? s->opt.listen_backlog : 1024;
    int r = uv_listen((uv_stream_t*)s->server, backlog, on_connection);
    if (r != 0) return -1;
    return uv_run((uv_loop_t*)s->loop, UV_RUN_DEFAULT);
}

void httpServer_close(http_server_t* s) {
        uv_close((uv_handle_t*)s->server, on_server_closed);
    for (size_t i = 0; i < s->bucket_len; i++) {
        route_entry* r = s->buckets[i].head;
        while (r) { route_entry* next = r->next; free_route(r); free(r); r = next; }
        free(s->buckets[i].key);
    }
    free(s->buckets); s->buckets = NULL; s->bucket_len = s->bucket_cap = 0;
    route_entry* r = s->routes; while (r) { route_entry* next = r->next; free_route(r); free(r); r = next; }
    s->routes = NULL;
}

static int add_route(http_server_t* s, unsigned method_mask, const char* pattern, http_handler_t h) {
    route_entry* r = (route_entry*)calloc(1, sizeof(route_entry));
    r->method_mask = method_mask;
    parse_route_pattern(pattern[0]=='/'?pattern+1:pattern, &r->segs, &r->seg_count);
    r->handler = h;
    if (r->seg_count > 0 && r->segs[0].type == SEG_LITERAL) {
        struct route_bucket* b = ensure_bucket(s, r->segs[0].text);
        r->next = b->head; b->head = r;
    } else {
        r->next = s->routes; s->routes = r;
    }
    return 0;
}

int httpServer_get(http_server_t* s, const char* path, http_handler_t handler) { return add_route(s, 1<<0, path, handler); }
int httpServer_post(http_server_t* s, const char* path, http_handler_t handler) { return add_route(s, 1<<1, path, handler); }
int httpServer_put(http_server_t* s, const char* path, http_handler_t handler) { return add_route(s, 1<<2, path, handler); }
int httpServer_delete(http_server_t* s, const char* path, http_handler_t handler) { return add_route(s, 1<<3, path, handler); }
int httpServer_patch(http_server_t* s, const char* path, http_handler_t handler) { return add_route(s, 1<<4, path, handler); }
int httpServer_head(http_server_t* s, const char* path, http_handler_t handler) { return add_route(s, 1<<5, path, handler); }
int httpServer_options(http_server_t* s, const char* path, http_handler_t handler) { return add_route(s, 1<<6, path, handler); }
int httpServer_any(http_server_t* s, const char* path, http_handler_t handler) { return add_route(s, 0, path, handler); }

const char* req_url(http_req_t* req) { return req->conn->urlp.url; }
const char* req_method(http_req_t* req) { return req->conn->method; }
int req_aborted(http_req_t* req) { return req->conn->closed; }
const char* req_getHeader(http_req_t* req, const char* key) { if (!key || !*key) return ""; const char* v = header_list_get(&req->conn->headers, key); return v ? v : ""; }

static const char* query_get(const char* query, const char* key) {
    size_t klen = strlen(key);
    const char* p = query; while (*p) {
        const char* amp = strchr(p, '&'); const char* end = amp ? amp : p + strlen(p);
        const char* eq = strchr(p, '='); if (!eq || eq > end) { if (!amp) break; p = amp + 1; continue; }
        if ((size_t)(eq - p) == klen && strncmp(p, key, klen) == 0) {
            size_t vlen = (size_t)(end - eq - 1); char* v = str_dup_range(eq + 1, vlen);
            return v;
        }
        if (!amp){
            break;
        }
        p = amp + 1;
    }
    return NULL;
}

const char* req_getQuery(http_req_t* req, const char* key) { if (!key || !*key) return ""; if (req->query_tmp) { free(req->query_tmp); req->query_tmp = NULL; } const char* v = query_get(req->conn->urlp.query, key); if (!v) return ""; req->query_tmp = (char*)v; return req->query_tmp; }
const char* req_getParameter(http_req_t* req, const char* key) { if (!key || !*key) return ""; const char* v = params_get(&req->conn->params, key); return v ? v : ""; }
void req_onData(http_req_t* req, http_ondata_cb cb) { req->conn->onBody = cb; }
void req_onAborted(http_req_t* req, http_onaborted_cb cb) { req->conn->onaborted = cb; }
void req_close(http_req_t* req) { uv_close((uv_handle_t*)&req->conn->handle, on_conn_closed); req->conn->closed=1; }
void req_end(http_req_t* req) { if (req->conn->onBody && req->conn->current_res) req->conn->onBody(req, req->conn->current_res, NULL, 0, 1); }
void req_pause(http_req_t* req) { req->conn->paused = 1; uv_read_stop((uv_stream_t*)&req->conn->handle); }
void req_resume(http_req_t* req) { req->conn->paused = 0; uv_read_start((uv_stream_t*)&req->conn->handle, on_alloc, on_read); }
http_res_t* req_getResponse(http_req_t* req) { return req->conn->current_res; }

void res_writeStatus(http_res_t* res, int code, const char* phrase) { if (res->headers_locked) { fprintf(stderr, "Warning: headers already sent, writeStatus ignored\n"); return; } res->status_code=code; res->status_phrase=phrase; }
void res_writeHeader(http_res_t* res, const char* key, const char* value) { if (res->headers_locked) { fprintf(stderr, "Warning: headers already sent, writeHeader ignored\n"); return; } header_list_set(&res->header, key, value); }
void res_write(http_res_t* res, const unsigned char* chunk, size_t len) { res_write_internal(res, chunk, len, 0); }
void res_writeRaw(http_res_t* res, const unsigned char* chunk, size_t len) {
    if (res->ended) return;
    http_conn* c = res->conn;
    if (!res->headers_locked) {
        res->headers_locked = 1;
        res->writePhase = 0;
        c->response_started = 1;
        header_list_set(&res->header, "connection", c->server->opt.keep_alive ? "keep-alive" : "close");
        res->chunked = 1;
        header_list_set(&res->header, "transfer-encoding", STR_CHUNKED);
        int code = res->status_code ? res->status_code : 200; const char* phrase = res->status_phrase ? res->status_phrase : "OK";
        char codebuf[16]; int cbl = snprintf(codebuf, sizeof(codebuf), "%d", code);
        uv_buf_t vec[64]; int n = 0;
        vec[n++] = uv_buf_init((char*)STR_HTTP11, (unsigned)strlen(STR_HTTP11));
        vec[n++] = uv_buf_init(codebuf, (unsigned)cbl);
        vec[n++] = uv_buf_init((char*)STR_SP, 1);
        vec[n++] = uv_buf_init((char*)phrase, (unsigned)strlen(phrase));
        vec[n++] = uv_buf_init((char*)STR_CRLF, 2);
        for (size_t i = 0; i < res->header.count; i++) { vec[n++] = uv_buf_init(res->header.items[i].key, (unsigned)strlen(res->header.items[i].key)); vec[n++] = uv_buf_init((char*)STR_COLON_SP, 2); vec[n++] = uv_buf_init(res->header.items[i].value, (unsigned)strlen(res->header.items[i].value)); vec[n++] = uv_buf_init((char*)STR_CRLF, 2); }
        vec[n++] = uv_buf_init((char*)STR_CRLF, 2);
        res_send_or_cork(res, vec, n, NULL, 0);
    }
    char* h = NULL; char* sfx = NULL; int hn = 0;
    char tmp[32]; hn = snprintf(tmp, sizeof(tmp), "%zx\r\n", len); h = (char*)malloc(hn); memcpy(h, tmp, hn);
    sfx = (char*)malloc(2); memcpy(sfx, "\r\n", 2);
    uv_buf_t bufs[3]; int nbufs = 0; bufs[nbufs++] = uv_buf_init(h, hn);
    if (len > 0) bufs[nbufs++] = uv_buf_init((char*)chunk, (unsigned)len);
    bufs[nbufs++] = uv_buf_init(sfx, 2);
    char** aux = (char**)malloc(3 * sizeof(char*)); aux[0] = h; aux[1] = sfx; aux[2] = NULL;
    res_send_or_cork(res, bufs, nbufs, aux, 2);
}
void res_end(http_res_t* res, const unsigned char* chunk, size_t len) { res_write_internal(res, chunk, len, 1); }
void res_close(http_res_t* res) { uv_close((uv_handle_t*)&res->conn->handle, on_conn_closed); res->conn->closed=1; }
void res_cork_start(http_res_t* res) { if (res->cork_scoped) { fprintf(stderr, "Warning: scoped cork active, start ignored\n"); return; } res->cork_manual = 1; if (!res->cork_limit) res->cork_limit = 64*1024; }
void res_cork_end(http_res_t* res) {
    if (!res->cork_manual) return;
    res->cork_manual = 0;
    cork_flush(res);
    if (res->ended) response_finalize(res); else cork_reset(res);
}
void res_cork(http_res_t* res, http_cork_cb cb) {
    if (res->cork_manual) { fprintf(stderr, "Warning: manual cork active, scoped cork ignored\n"); return; }
    res->cork_scoped = 1;
    if (!res->cork_limit) res->cork_limit = 64*1024;
    http_req_t* req = res->conn->current_req;
    cb(req, res);
    res->cork_scoped = 0;
    cork_flush(res);
    if (res->ended) response_finalize(res); else cork_reset(res);
}
static void on_timer_closed(uv_handle_t* h) {
    http_conn* c = (http_conn*)h->data;
    if (!c) return;
    header_list_free(&c->headers);
    url_parts_free(&c->urlp);
    free(c->readbuf);
    params_free(&c->params);
    if (c->raw_header) free(c->raw_header);
    if (c->current_req) { if (c->current_req->query_tmp) free(c->current_req->query_tmp); free(c->current_req->remoteAddress); }
    free(c->current_req);
    free(c->current_res);
    free(c);
}

static void on_conn_closed(uv_handle_t* h) {
    http_conn* c = (http_conn*)h->data;
    if (c && c->current_req) c->current_req->aborted = 1;
    if (c && c->server && c->server->conn_count) c->server->conn_count--;
    if (c) {
        uv_timer_stop(&c->ka_timer);
        uv_close((uv_handle_t*)&c->ka_timer, on_timer_closed);
    }
}

static void on_keepalive_timeout(uv_timer_t* t) {
    http_conn* c = (http_conn*)t->data;
    if (!c) return;
    uv_close((uv_handle_t*)&c->handle, on_conn_closed);
}
int res_removeHeader(http_res_t* res, const char* key) {
    if (res->headers_locked) return 0;
    if (!key || !*key) return 0;
    return header_list_remove(&res->header, key);
}
