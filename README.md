# qHttpServer
A high-performance HTTP1.1 Web application framework based on libuv

- 高性能
- 轻量

---

## 依赖要求
- libuv 库（>= 1.0.0）

---

### httpServer(opt)
**接口说明**：HTTP服务器初始化入口，通过配置参数创建服务器实例。
| 参数名 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| max_connections | Number | 0 | 每个worker进程最大并发连接数，0表示不限制 |
| keep_alive | Boolean | true | 是否开启长连接（需配合以下超时/请求数参数使用） |
| keep_alive_timeout | Number | - | 长连接超时时间（单位：毫秒），超时后关闭连接 |
| keep_alive_requests | Number | 0 | 单个长连接允许处理的最大请求数，0表示不限制 |
| worker_processes | Number | CPU核心数量 | 工作进程数，默认按CPU核心数分配 |
| max_header_size | Number | 0 | 请求头最大允许大小（单位：字节），超出则拒绝请求，0表示不限制 |
| listen_backlog | Number | 1024 | 连接队列的最大长度 |

### 路由方法
**接口说明**：注册HTTP请求路由，支持不同请求方法及路由参数、通配符。
**参数说明**：path=路由路径（支持`:参数`和`*`通配符）；handler=请求处理函数
| 接口名 | 说明 |
|--------|------|
| httpServer->get(path, handler) | 注册GET请求路由 |
| httpServer->post(path, handler) | 注册POST请求路由 |
| httpServer->any(path, handler)| 注册匹配所有请求方法的路由 |
| httpServer->put(path, handler)| 注册PUT请求路由 |
| httpServer->delete(path, handler)| 注册DELETE请求路由 |
| httpServer->patch(path, handler)| 注册PATCH请求路由 |
| httpServer->head(path, handler)| 注册HEAD请求路由 |
| httpServer->options(path, handler)| 注册OPTIONS请求路由 |

### 服务器启停
| 接口名 | 参数 | 说明 |
|--------|------|------|
| httpServer->Listen(port, ip) | port：整形，端口号；ip：可选,字符串，绑定的IP地址，默认全部:0.0.0.0 |
| httpServer->close() | 无 | 关闭服务器，释放端口和连接资源 |

### res
**接口说明**：用于构建并发送HTTP响应，操作需遵循调用顺序（body输出后再调用状态/头方法会失效）。使用res->write为流式传输，不需要Content-Length。
| 接口名 | 参数 | 说明 |
|--------|------|------|
| res->writeStatus(code, phrase) | code：HTTP状态码（Number）；phrase：状态描述（String，如"OK"） | 设置响应状态码及描述 |
| res->header | - | 响应头容器，动态读写，动态读写容器，所有键需用小写写入。 |
| res->writePhase() | - | 动态，只读，当前写入响应体状态，返回-1未写 0已开始写 1写完 |
| res->writeHeader(key, value) | key：响应头名；value：响应头值 | 单个设置响应头 |
| res->removeHeader(key) | key:移除的响应头key字符串 | 移除指定响应头,不存在或已传输返回false,返回布尔值true/false |
| res->write(chunk,len) | chunk：二进制/字符串数据；len:字节整形,数据长度 | 流式写入响应体，调用后再执行writeStatus/writeHeader会忽略并输出警告 |
| res->writeRaw(chunk,len) | chunk：二进制/字符串数据；len:字节整形,数据长度 | 零拷贝，流式写入响应体，需确保chunk在写入之前不修改销毁，异常给予警告 |
| res->end(chunk,len) | chunk（可选）：二进制/字符串/空；len:字节整形,数据长度 | 结束响应，res->write之后使用res->end结束或补充最后chunk并结束 |
| res->close() | - | 强制关闭响应连接，终止响应发送 |
| res->cork_start(res) | res | 启用cork，优化小数据包的批量发送场景 |
| res->cork_end(res) | res | 解用cork，提交 cork 期间的写请求 |
| res->cork(cb) | 回调函数(res,req) | 回调使用cork |

### req
**接口说明**：封装客户端请求信息，支持请求数据读取、连接控制。
| 接口名 | 参数 | 说明 |
|--------|------|------|
| req->url | - | 只读，请求完整URL（含路径和Query） |
| req->path | - | 只读，请求完整路径 |
| req->query | - | 只读，请求完整Query字符串 |
| req->remoteAddres | - | 只读，客户端远程IP地址 |
| req->method | - | 只读，请求方法（GET/POST等，大写） |
| req->rawHeader | - | 只读，原始请求头，字符串 |
| req->header | - | 只读，请求头，只读字典视图，所有键为小写；header_size(req->header) 返回项数 ；header_key(req->header, i) 返回第 i 条的键；header_value(req->header, i) 返回第 i 条的值 |
| req->aborted | - | 动态，只读，连接是否已终止（布尔值：true/false） |
| req->parameter | key：字符串，路由参数名 | 只读，获取key的路由参数值，字符串，空则返回空字符串 |
| req->getHeader(key) | key：字符串，请求头名 | 获取key的请求头值，字符串，空则返回空字符串，默认空 |
| req->getQuery(key) | key：字符串，Query参数名 | 获取key的URL Query参数值，空则返回空字符串，默认空 |
| req->getParameter(key) | key：字符串，路由参数名 | 获取路由参数（如`/user/:id`中的id的值），空则返回空字符串，默认空 |
| req->onData(callback) | callback：(chunk, isLast) => {} | 注册请求体数据接收回调，chunk为二进制数据，isLast表示是否为最后一段数据，布尔值；无请求数据的method无需触发 |
| req->onAborted(callback) | callback：() => {} | 注册连接中断回调，连接终止时触发 |
| req->close() | - | 强制关闭请求连接 |
| req->end() | - | 结束体流式传输请求体，且无法暂停和恢复；存在onData的回调，chunk为空，isLast为true |
| req->pause() | - | 暂停请求体流式传输请求体，暂停后onData不再触发 |
| req->resume() | - | 恢复请求体流式传输请求体，恢复后onData继续触发 |
