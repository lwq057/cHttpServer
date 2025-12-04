#include <stdio.h>
#include <string.h>
#include "../src/httpserver.h"

static void hello_handler(http_req_t* req, http_res_t* res) {
    const char* name = req->getParameter("name");
    char buf[2048];
    if (!name) {
        name = "world";
    }
    const char* query = req->query;
    const char* url = req->url;
    const char* path = req->path;
    const char* method = req->method;
    const char* aborted = req->aborted ? "true" : "false";
    const char* remote_addr = req->remoteAddress;
    const char* ua = req->getHeader("user-agent");
    const char* id = req->getQuery("id");
    const int phase = res->writePhase;
    const char* raw = req->rawHeader;
    res->writeHeader("server","Nginx/100861");
    res->removeHeader("x-custom");
    int n = snprintf(buf, sizeof(buf), "<meta charset=\"UTF-8\"><pre>Hello World！\n\nname:%s\nid:%s\nquery:%s\nurl:%s\npath:%s\nmethod:%s\naborted:%s\nremote_addr:%s\nua:%s\nphase:%d\n\nheaders:\n%s<pre>",name, id, query, url, path, method, aborted, remote_addr, ua, phase, raw ? raw : "");
    res->writeHeader("Content-Type", "text/html; charset=utf-8");
    res->end((const unsigned char*)buf, (size_t)n);
}

static void echo_ondata(http_req_t* req, http_res_t* res, const unsigned char* chunk, size_t len, int is_last) {
    if (chunk && len) { res->writeRaw(chunk, len); }
    if (is_last) { res->end(NULL, 0); }
}

static void echo_handler(http_req_t* req, http_res_t* res) {
    res->writeStatus(200, "OK");
    res->writeHeader("Content-Type", "application/octet-stream");
    req->onData(echo_ondata);
}

static void headers_handler(http_req_t* req, http_res_t* res) {
    char out[8192]; size_t off = 0;
    res->writeHeader("content-type", "text/plain; charset=utf-8");
    res->writeHeader("x-demo", "1");
    res->removeHeader("x-demo");
    off += snprintf(out+off, sizeof(out)-off, "req.headers:\n");
    const header_list* rhl = req->header;
    for (size_t i = 0; i < header_size(rhl) && off < sizeof(out); i++) {
        const char* k = header_key(rhl, i);
        const char* v = header_value(rhl, i);
        off += snprintf(out+off, sizeof(out)-off, "%s: %s\n", k ? k : "", v ? v : "");
    }
    off += snprintf(out+off, sizeof(out)-off, "\nres.headers:\n");
    const header_list* shl = (const header_list*)&res->header;
    for (size_t i = 0; i < header_size(shl) && off < sizeof(out); i++) {
        const char* k = header_key(shl, i);
        const char* v = header_value(shl, i);
        off += snprintf(out+off, sizeof(out)-off, "%s: %s\n", k ? k : "", v ? v : "");
    }
    res->end((const unsigned char*)out, (size_t)off);
}

static void cork_cb(http_req_t* req, http_res_t* res) {
    (void)req;
    res->writeStatus(200, "OK");
    res->writeHeader("Content-Type", "text/plain; charset=utf-8");
    const char* body = "Hello Cork Done";
    res->end((const unsigned char*)body, strlen(body));
}

static void cork_handler(http_req_t* req, http_res_t* res) { res->cork(cork_cb); }

static void cork_manual_handler(http_req_t* req, http_res_t* res) {
    (void)req;
    res->cork_start();
    res->writeStatus(200, "OK");
    res->writeHeader("Content-Type", "text/plain; charset=utf-8");
    const char* body = "Hello Manual Cork";
    res->end((const unsigned char*)body, strlen(body));
    res->cork_end();
}

int main() {
    http_server_options_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.keep_alive = 1;
    opt.keep_alive_timeout = 30000;
    http_server_t* s = httpServer(&opt);
    s->get("/hello/:name", hello_handler);
    s->post("/echo", echo_handler);
    s->get("/headers", headers_handler);
    s->get("/cork", cork_handler);
    s->get("/cork-manual", cork_manual_handler);
    s->get("/*", hello_handler);
    printf("Listening on 0.0.0.0:8080\n");
    return s->listen(8080, "0.0.0.0");
}
