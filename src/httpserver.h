#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#include <stddef.h>
#include <stdint.h>

typedef struct http_server http_server_t;
typedef struct http_req http_req_t;
typedef struct http_res http_res_t;
typedef struct http_conn http_conn;

typedef struct header_kv { char* key; char* value; } header_kv;
typedef struct header_list { header_kv* items; size_t count; size_t cap; } header_list;
typedef struct param_kv { char* key; char* val; } param_kv;
typedef struct param_list { param_kv* items; size_t count; size_t cap; } param_list;
typedef struct route_entry route_entry;
typedef struct route_bucket route_bucket;

typedef void (*http_handler_t)(http_req_t* req, http_res_t* res);
typedef void (*http_ondata_cb)(http_req_t* req, http_res_t* res, const unsigned char* chunk, size_t len, int is_last);
typedef void (*http_onaborted_cb)(void);
typedef void (*http_cork_cb)(http_req_t* req, http_res_t* res);

typedef struct {
    size_t max_connections;
    int keep_alive;
    uint64_t keep_alive_timeout;
    size_t keep_alive_requests;
    size_t worker_processes;
    size_t max_header_size;
    int listen_backlog;
} http_server_options_t;

struct http_server {
    void* loop;
    void* server;
    http_server_options_t opt;
    route_entry* routes;
    route_bucket* buckets;
    size_t bucket_len;
    size_t bucket_cap;
    size_t conn_count;
    int (*listen)(int port, const char* ip);
    void (*close)(void);
    int (*get)(const char* path, http_handler_t handler);
    int (*post)(const char* path, http_handler_t handler);
    int (*any)(const char* path, http_handler_t handler);
    int (*put)(const char* path, http_handler_t handler);
    int (*delete)(const char* path, http_handler_t handler);
    int (*patch)(const char* path, http_handler_t handler);
    int (*head)(const char* path, http_handler_t handler);
    int (*options)(const char* path, http_handler_t handler);
};
 
struct http_req {
    http_conn* conn;
    const char* url;
    const char* path;
    const char* query;
    const char* rawHeader;
    char* remoteAddress;
    const char* method;
    int aborted;
    const header_list* header;
    const param_list* parameter;
    char* query_tmp;
    const char* (*getHeader)(const char* key);
    const char* (*getQuery)(const char* key);
    const char* (*getParameter)(const char* key);
    void (*onData)(http_ondata_cb cb);
    void (*onAborted)(http_onaborted_cb cb);
    void (*close)(void);
    void (*end)(void);
    void (*pause)(void);
    void (*resume)(void);
    http_res_t* (*getResponse)(void);
};

struct http_res {
    http_conn* conn;
    int status_code;
    const char* status_phrase;
    header_list header;
    int headers_locked;
    int chunked;
    int ended;
    int cork_manual;
    int cork_scoped;
    void* cork_bufs;
    int cork_count;
    int cork_cap;
    char** cork_dyn_ptrs;
    int cork_dyn_count;
    int cork_dyn_cap;
    size_t cork_bytes;
    size_t cork_limit;
    void (*writeStatus)(int code, const char* phrase);
    void (*writeHeader)(const char* key, const char* value);
    int (*removeHeader)(const char* key);
    void (*write)(const unsigned char* chunk, size_t len);
    void (*writeRaw)(const unsigned char* chunk, size_t len);
    void (*end)(const unsigned char* chunk, size_t len);
    void (*close)(void);
    void (*cork_start)(void);
    void (*cork_end)(void);
    void (*cork)(http_cork_cb cb);
    int writePhase;
};

http_server_t* httpServer(const http_server_options_t* opt);
int httpServer_listen(http_server_t* s, int port, const char* ip);
void httpServer_close(http_server_t* s);

int httpServer_get(http_server_t* s, const char* path, http_handler_t handler);
int httpServer_post(http_server_t* s, const char* path, http_handler_t handler);
int httpServer_any(http_server_t* s, const char* path, http_handler_t handler);
int httpServer_put(http_server_t* s, const char* path, http_handler_t handler);
int httpServer_delete(http_server_t* s, const char* path, http_handler_t handler);
int httpServer_patch(http_server_t* s, const char* path, http_handler_t handler);
int httpServer_head(http_server_t* s, const char* path, http_handler_t handler);
int httpServer_options(http_server_t* s, const char* path, http_handler_t handler);
int res_removeHeader(http_res_t* res, const char* key);

const char* req_url(http_req_t* req);
const char* req_method(http_req_t* req);
int req_aborted(http_req_t* req);
const char* req_getHeader(http_req_t* req, const char* key);
const char* req_getQuery(http_req_t* req, const char* key);
const char* req_getParameter(http_req_t* req, const char* key);
void req_onData(http_req_t* req, http_ondata_cb cb);
void req_onAborted(http_req_t* req, http_onaborted_cb cb);
void req_close(http_req_t* req);
void req_end(http_req_t* req);
void req_pause(http_req_t* req);
void req_resume(http_req_t* req);
http_res_t* req_getResponse(http_req_t* req);

void res_writeStatus(http_res_t* res, int code, const char* phrase);
void res_writeHeader(http_res_t* res, const char* key, const char* value);
void res_write(http_res_t* res, const unsigned char* chunk, size_t len);
void res_writeRaw(http_res_t* res, const unsigned char* chunk, size_t len);
void res_end(http_res_t* res, const unsigned char* chunk, size_t len);
void res_close(http_res_t* res);
void res_cork_start(http_res_t* res);
void res_cork_end(http_res_t* res);
void res_cork(http_res_t* res, http_cork_cb cb);

static inline size_t header_size(const header_list* hl) { return hl ? hl->count : 0; }
static inline const header_kv* header_at(const header_list* hl, size_t i) { return hl ? &hl->items[i] : (const header_kv*)0; }
static inline const char* header_key(const header_list* hl, size_t i) { return hl ? hl->items[i].key : (const char*)0; }
static inline const char* header_value(const header_list* hl, size_t i) { return hl ? hl->items[i].value : (const char*)0; }
static inline size_t param_size(const param_list* pl) { return pl ? pl->count : 0; }
static inline const param_kv* param_at(const param_list* pl, size_t i) { return pl ? &pl->items[i] : (const param_kv*)0; }
static inline const char* param_key(const param_list* pl, size_t i) { return pl ? pl->items[i].key : (const char*)0; }
static inline const char* param_value(const param_list* pl, size_t i) { return pl ? pl->items[i].val : (const char*)0; }

#endif
