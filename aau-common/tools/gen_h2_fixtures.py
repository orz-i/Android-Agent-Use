#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用参考实现（hpack / h2）生成 HTTP/2 字节流测试向量。

思路：HPACK 头块交给 hpack.Encoder（真实 Huffman + 动态表），
帧封装由本脚本按 RFC 7540 拼装（这样才能精确制造 PADDED / PRIORITY /
CONTINUATION 等边界情况），最后用 h2 的 server 端反向解析整条流做自校验。

用法（模块根目录下）：

    python tools/gen_h2_fixtures.py

默认把夹具写到 `src/test/java/com/agent/use/common/network/parser/H2ConformanceFixtures.kt`。
改完生成器后重跑一次即可，Kotlin 侧不需要手工同步。
需要可读副本排查时传一个路径当第一个参数，例如 `python tools/gen_h2_fixtures.py out.json`。
"""
import base64
import os
import gzip
import json
import struct
import sys

import h2.config
import h2.connection
import h2.events
import hpack

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = range(10)
END_STREAM, END_HEADERS, PADDED, PRIORITY_FLAG = 0x1, 0x4, 0x8, 0x20


def frame(ftype, flags, sid, payload=b""):
    assert len(payload) < 1 << 24
    return (
        struct.pack(">I", len(payload))[1:]
        + bytes([ftype, flags])
        + struct.pack(">I", sid & 0x7FFFFFFF)
        + payload
    )


def headers_payload(block, pad_len=None, priority=None):
    out = b""
    if pad_len is not None:
        out += bytes([pad_len])
    if priority is not None:
        out += struct.pack(">I", priority[0] & 0x7FFFFFFF) + bytes([priority[1]]) + priority[2]
    out += block
    if pad_len is not None:
        out += b"\x00" * pad_len
    return out


def headers_frame(block, sid, end_stream=False, end_headers=True, pad_len=None, priority=None):
    flags = 0
    if end_stream:
        flags |= END_STREAM
    if end_headers:
        flags |= END_HEADERS
    if pad_len is not None:
        flags |= PADDED
    if priority is not None:
        flags |= PRIORITY_FLAG
    return frame(HEADERS, flags, sid, headers_payload(block, pad_len, priority))


def data_frame(data, sid, end_stream=False, pad_len=None):
    flags = END_STREAM if end_stream else 0
    payload = data
    if pad_len is not None:
        flags |= PADDED
        payload = bytes([pad_len]) + data + b"\x00" * pad_len
    return frame(DATA, flags, sid, payload)


def split_continuation(block, sid, end_stream, chunk):
    """把头块拆成 HEADERS + 若干 CONTINUATION，模拟超过 max frame size 的情形。"""
    parts = [block[i:i + chunk] for i in range(0, len(block), chunk)]
    out = b""
    first = parts[0]
    flags = (END_STREAM if end_stream else 0) | (END_HEADERS if len(parts) == 1 else 0)
    out += frame(HEADERS, flags, sid, first)
    for i, part in enumerate(parts[1:]):
        last = i == len(parts) - 2
        out += frame(CONTINUATION, END_HEADERS if last else 0, sid, part)
    return out


def settings(entries=()):
    payload = b"".join(struct.pack(">HI", k, v) for k, v in entries)
    return frame(SETTINGS, 0, 0, payload)


class Conn:
    """一条方向独立的帧构造器，持有自己的 hpack 编码器（动态表按方向隔离）。"""

    def __init__(self, with_preface=False):
        self.enc = hpack.Encoder()
        self.buf = PREFACE if with_preface else b""
        self.buf += settings()

    def headers(self, sid, pairs, **kw):
        block = self.enc.encode(pairs)
        self.buf += headers_frame(block, sid, **kw)
        return block

    def split_headers(self, sid, pairs, chunk, **kw):
        block = self.enc.encode(pairs)
        self.buf += split_continuation(block, sid, kw.get("end_stream", False), chunk)
        return block

    def data(self, sid, data, **kw):
        self.buf += data_frame(data, sid, **kw)

    def raw(self, b):
        self.buf += b


def resp_pairs(status, extra):
    return [(b":status", str(status).encode())] + [
        (k.encode() if isinstance(k, str) else k, v.encode() if isinstance(v, str) else v)
        for k, v in extra
    ]


def req_pairs(method, authority, path, extra):
    pairs = [
        (b":method", method.encode()),
        (b":scheme", b"https"),
        (b":authority", authority.encode()),
        (b":path", path.encode()),
    ]
    pairs += [
        (k.encode() if isinstance(k, str) else k, v.encode() if isinstance(v, str) else v)
        for k, v in extra
    ]
    return pairs


def _norm_headers(headers):
    out = {}
    for k, v in headers:
        if isinstance(k, bytes):
            k = k.decode("utf-8", "replace")
        if isinstance(v, bytes):
            v = v.decode("utf-8", "replace")
        out[k] = v
    return out


def validate(outbound, expect_requests):
    """用 h2 的 server 端反向解析客户端字节流，确认帧与 HPACK 都是合法的。"""
    srv = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
    )
    srv.initiate_connection()
    events = srv.receive_data(outbound)
    got = [_norm_headers(e.headers) for e in events if isinstance(e, h2.events.RequestReceived)]
    if len(got) != len(expect_requests):
        raise SystemExit(
            f"h2 参考解析得到 {len(got)} 个请求，期望 {len(expect_requests)}"
        )
    for headers, (method, path) in zip(got, expect_requests):
        if headers.get(":method") != method or headers.get(":path") != path:
            raise SystemExit(
                f"h2 解析不一致: {headers.get(':method')} {headers.get(':path')} != {method} {path}"
            )
    return True


def b64(b):
    return base64.b64encode(b).decode()


FIXTURES = []


def add(name, client, server, requests, responses, note="", validate_stream=True, validate_reqs=None):
    raw_reqs = validate_reqs if validate_reqs is not None else requests
    if raw_reqs and not isinstance(raw_reqs[0], dict):
        req_check = [tuple(x) for x in raw_reqs]
    else:
        req_check = [(r["method"], r["path"]) for r in raw_reqs]
    if validate_stream:
        validate(client.buf, req_check)
    FIXTURES.append(
        {
            "name": name,
            "note": note,
            "outbound": b64(client.buf),
            "inbound": b64(server.buf),
            "requests": requests,
            "responses": responses,
        }
    )
    print(f"  {name:28s} out={len(client.buf):5d}B in={len(server.buf):5d}B "
          f"req={len(requests)} resp={len(responses)}")


# ---------------------------------------------------------------- s1: 基础 GET
def s1():
    body = json.dumps({"code": 0, "zpData": {"jobList": [{"jobName": "Android"}]}}, ensure_ascii=False).encode()
    c = Conn(with_preface=True)
    c.headers(1, req_pairs("GET", "api.example.com", "/v1/feed?tag=a+b", [
        ("user-agent", "boss/13.0"), ("accept", "application/json"),
    ]), end_stream=True)
    s = Conn()
    s.headers(1, resp_pairs(200, [("content-type", "application/json"),
                                  ("content-length", str(len(body)))]))
    s.data(1, body, end_stream=True)
    add("basic_get", c, s,
        [{"stream": 1, "method": "GET", "path": "/v1/feed?tag=a+b",
          "url": "https://api.example.com/v1/feed?tag=a+b"}],
        [{"stream": 1, "status": 200, "contentType": "application/json", "body": body.decode()}],
        validate_stream=False)


# ------------------------------------------------------- s2: POST 分片 + 多 DATA
def s2():
    payload = json.dumps({"phone": "13800000000", "code": "1234"}).encode()
    resp = json.dumps({"code": 0, "token": "abc"}).encode()
    c = Conn(with_preface=True)
    c.headers(1, req_pairs("POST", "www.zhipin.com", "/wapi/zpuser/login", [
        ("content-type", "application/json"), ("content-length", str(len(payload))),
    ]))
    c.data(1, payload[:7])
    c.data(1, payload[7:], end_stream=True)
    s = Conn()
    s.headers(1, resp_pairs(200, [("content-type", "application/json"),
                                  ("content-length", str(len(resp)))]))
    s.data(1, resp[:5])
    s.data(1, resp[5:], end_stream=True)
    add("post_split_data", c, s,
        [{"stream": 1, "method": "POST", "path": "/wapi/zpuser/login",
          "url": "https://www.zhipin.com/wapi/zpuser/login", "postContains": payload.decode()}],
        [{"stream": 1, "status": 200, "contentType": "application/json", "body": resp.decode()}])


# ------------------------------------------- s3: PADDED + PRIORITY + 大 padding
def s3():
    body = b'{"ok":true,"padding_test":1}'
    c = Conn(with_preface=True)
    block = c.enc.encode(req_pairs("GET", "api.example.com", "/v1/padded", []))
    c.raw(headers_frame(block, 3, end_stream=True, pad_len=13, priority=(0, 200, b"")))
    s = Conn()
    rb = s.enc.encode(resp_pairs(200, [("content-type", "application/json"),
                                       ("content-length", str(len(body)))]))
    s.raw(headers_frame(rb, 3, pad_len=7))
    s.raw(data_frame(body, 3, end_stream=True, pad_len=5))
    add("padded_priority", c, s,
        [{"stream": 3, "method": "GET", "path": "/v1/padded",
          "url": "https://api.example.com/v1/padded"}],
        [{"stream": 3, "status": 200, "contentType": "application/json", "body": body.decode()}])


# ---------------------------------------------------- s4: CONTINUATION 分片头块
def s4():
    body = b'{"cont":1}'
    big = ("x-trace-payload", "T" * 900)
    c = Conn(with_preface=True)
    c.split_headers(5, req_pairs("GET", "api.example.com", "/v1/continuation", [big]),
                    chunk=120, end_stream=True)
    s = Conn()
    rblock = s.enc.encode(resp_pairs(200, [("content-type", "application/json"),
                                           ("content-length", str(len(body))), big]))
    s.raw(split_continuation(rblock, 5, False, 100))
    s.data(5, body, end_stream=True)
    add("continuation_split", c, s,
        [{"stream": 5, "method": "GET", "path": "/v1/continuation",
          "url": "https://api.example.com/v1/continuation"}],
        [{"stream": 5, "status": 200, "contentType": "application/json", "body": body.decode(),
          "headerPresent": "x-trace-payload"}])


# ------------------------------------------------------------ s5: 响应尾部 trailer
def s5():
    body = b'{"trailer":true}'
    c = Conn(with_preface=True)
    c.headers(7, req_pairs("POST", "api.example.com", "/v1/trailer", []), end_stream=True)
    s = Conn()
    s.headers(7, resp_pairs(200, [("content-type", "application/json")]))
    s.data(7, body)
    s.headers(7, [(b"x-checksum", b"deadbeef")], end_stream=True)
    add("response_trailers", c, s,
        [{"stream": 7, "method": "POST", "path": "/v1/trailer",
          "url": "https://api.example.com/v1/trailer"}],
        [{"stream": 7, "status": 200, "contentType": "application/json", "body": body.decode(),
          "headerPresent": "x-checksum"}])


# ------------------------------------------- s6: 动态表复用 + 表大小更新 + 多流
def s6():
    c = Conn(with_preface=True)
    s = Conn()
    for i, sid in enumerate((1, 3, 5), start=1):
        path = f"/v1/items?page={i}"
        c.headers(sid, req_pairs("GET", "api.example.com", path, [
            ("accept-encoding", "gzip, deflate"),
            ("x-session", "S" * 40),
        ]), end_stream=True)
        body = json.dumps({"page": i}).encode()
        s.headers(sid, resp_pairs(200, [("content-type", "application/json"),
                                        ("content-length", str(len(body))),
                                        ("x-session", "S" * 40)]))
        s.data(sid, body, end_stream=True)
        if i == 2:
            # 触发 Dynamic Table Size Update（001xxxxx 前缀）
            c.enc.header_table_size = 256
            s.enc.header_table_size = 256
    add("dynamic_table_reuse", c, s,
        [{"stream": sid, "method": "GET", "path": f"/v1/items?page={i}",
          "url": f"https://api.example.com/v1/items?page={i}"}
         for i, sid in zip((1, 2, 3), (1, 3, 5))],
        [{"stream": sid, "status": 200, "contentType": "application/json",
          "body": json.dumps({"page": i})}
         for i, sid in zip((1, 2, 3), (1, 3, 5))])


# --------------------------------------------------------------- s7: RST_STREAM
def s7():
    c = Conn(with_preface=True)
    c.headers(9, req_pairs("GET", "api.example.com", "/v1/abort", []), end_stream=True)
    s = Conn()
    s.headers(9, resp_pairs(200, [("content-type", "text/plain")]))
    s.data(9, b"partial-body")
    s.raw(frame(RST_STREAM, 0, 9, struct.pack(">I", 0x8)))  # CANCEL
    add("rst_stream", c, s,
        [{"stream": 9, "method": "GET", "path": "/v1/abort",
          "url": "https://api.example.com/v1/abort"}],
        [{"stream": 9, "status": 200, "contentType": "text/plain", "body": "partial-body"}])


# ------------------------------------------------------ s8: 1xx 临时响应后跟 200
def s8():
    body = b'{"after":103}'
    c = Conn(with_preface=True)
    c.headers(11, req_pairs("GET", "api.example.com", "/v1/early", []), end_stream=True)
    s = Conn()
    s.headers(11, resp_pairs(100, []))
    s.headers(11, resp_pairs(200, [("content-type", "application/json"),
                                   ("content-length", str(len(body)))]))
    s.data(11, body, end_stream=True)
    add("informational_100", c, s,
        [{"stream": 11, "method": "GET", "path": "/v1/early",
          "url": "https://api.example.com/v1/early"}],
        [{"stream": 11, "status": 200, "contentType": "application/json", "body": body.decode()}])


# ------------------------------------------------------ s9: content-encoding gzip
def s9():
    raw = json.dumps({"gzip": True, "items": list(range(20))}).encode()
    body = gzip.compress(raw)
    c = Conn(with_preface=True)
    c.headers(13, req_pairs("GET", "api.example.com", "/v1/gzip", []), end_stream=True)
    s = Conn()
    s.headers(13, resp_pairs(200, [("content-type", "application/json"),
                                   ("content-encoding", "gzip")]))
    s.data(13, body[:10])
    s.data(13, body[10:], end_stream=True)
    add("gzip_response", c, s,
        [{"stream": 13, "method": "GET", "path": "/v1/gzip",
          "url": "https://api.example.com/v1/gzip"}],
        [{"stream": 13, "status": 200, "contentType": "application/json", "body": raw.decode()}])


# ------------------------------------- s10: 中途接入（无 preface）+ 服务端推送
def s10():
    body = b'{"mid":1}'
    c = Conn(with_preface=False)  # 无 preface，模拟中途 attach
    c.headers(1, req_pairs("GET", "api.example.com", "/v1/mid", []), end_stream=True)
    s = Conn()
    # PUSH_PROMISE 声明 stream 2，随后 2 上推 HEADERS/DATA
    s.headers(1, resp_pairs(200, [("content-type", "application/json"),
                                  ("content-length", str(len(body)))]))
    s.data(1, body, end_stream=True)
    add("midstream_no_preface", c, s,
        [{"stream": 1, "method": "GET", "path": "/v1/mid",
          "url": "https://api.example.com/v1/mid"}],
        [{"stream": 1, "status": 200, "contentType": "application/json", "body": body.decode()}],
        validate_stream=False)


KT_HEADER = '''package com.agent.use.common.network.parser

/**
 * HTTP/2 + HPACK 一致性夹具，由 `aau-common/tools/gen_h2_fixtures.py` 生成，**请勿手改**。
 *
 * 生成方式决定了它的可信度：
 * - HPACK 头块由参考实现 `python-hpack` 编码（真实 Huffman + 动态表索引）
 * - 帧封装按 RFC 7540 手工拼装，用于精确制造 PADDED / PRIORITY / CONTINUATION 边界
 * - 每条客户端字节流都由 `python-h2` 的 server 端反向解析校验过
 *
 * 所以这些字节流不是"我认为对的格式"，而是第三方实现产出的、可互操作的格式。
 */
internal object H2ConformanceFixtures {

    class ExpectedRequest(
        val stream: Int,
        val method: String,
        val url: String,
        val postContains: String?
    )

    class ExpectedResponse(
        val stream: Int,
        val status: Int,
        val contentType: String?,
        val body: String,
        val extraHeader: String?
    )

    class Case(
        val name: String,
        val outboundB64: String,
        val inboundB64: String,
        val requests: List<ExpectedRequest>,
        val responses: List<ExpectedResponse>
    )

    val CASES: List<Case> = listOf(
'''


def kotlin_str(s):
    out = s.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    out = out.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return '"' + out + '"'


def emit_kotlin(path):
    parts = [KT_HEADER]
    for case in FIXTURES:
        req_lines = []
        for r in case["requests"]:
            post = kotlin_str(r["postContains"]) if r.get("postContains") else "null"
            req_lines.append(
                f"                ExpectedRequest({r['stream']}, {kotlin_str(r['method'])}, "
                f"{kotlin_str(r['url'])}, {post}),"
            )
        resp_lines = []
        for r in case["responses"]:
            ct = kotlin_str(r["contentType"]) if r.get("contentType") else "null"
            extra = kotlin_str(r["headerPresent"]) if r.get("headerPresent") else "null"
            resp_lines.append(
                f"                ExpectedResponse({r['stream']}, {r['status']}, {ct}, "
                f"{kotlin_str(r['body'])}, {extra}),"
            )
        parts.append(
            "        Case(\n"
            f"            name = {kotlin_str(case['name'])},\n"
            f"            outboundB64 = {kotlin_str(case['outbound'])},\n"
            f"            inboundB64 = {kotlin_str(case['inbound'])},\n"
            "            requests = listOf(\n" + "\n".join(req_lines) + "\n            ),\n"
            "            responses = listOf(\n" + "\n".join(resp_lines) + "\n            ),\n"
            "        ),\n"
        )
    parts.append("    )\n}\n")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("".join(parts))


# ------------------------------------------------- s11: GOAWAY 切断未完成的响应
def s11():
    body = b"partial-body-truncated"
    c = Conn(with_preface=True)
    c.headers(1, req_pairs("GET", "api.example.com", "/v1/goaway", []), end_stream=True)
    s = Conn()
    s.headers(1, resp_pairs(200, [("content-type", "text/plain")]))
    s.data(1, body)  # 故意不发 END_STREAM
    s.raw(frame(GOAWAY, 0, 0, struct.pack(">II", 0, 0)))  # lastStreamId = 0
    add("goaway_truncated", c, s,
        [{"stream": 1, "method": "GET", "path": "/v1/goaway",
          "url": "https://api.example.com/v1/goaway"}],
        [{"stream": 1, "status": 200, "contentType": "text/plain", "body": body.decode()}])


# ------------------------------------------------------------- s12: 服务端推送
def s12():
    main_body = b'{"push":"main"}'
    push_body = b'{"push":"asset"}'
    c = Conn(with_preface=True)
    c.headers(1, req_pairs("GET", "api.example.com", "/v1/push-main", []), end_stream=True)
    s = Conn()
    promise_block = s.enc.encode(req_pairs("GET", "api.example.com", "/v1/pushed", []))
    s.raw(frame(PUSH_PROMISE, END_HEADERS, 1, struct.pack(">I", 2) + promise_block))
    s.headers(1, resp_pairs(200, [("content-type", "application/json"),
                                  ("content-length", str(len(main_body)))]))
    s.data(1, main_body, end_stream=True)
    s.headers(2, resp_pairs(200, [("content-type", "application/json"),
                                  ("content-length", str(len(push_body)))]))
    s.data(2, push_body, end_stream=True)
    add("push_promise", c, s,
        [{"stream": 1, "method": "GET", "path": "/v1/push-main",
          "url": "https://api.example.com/v1/push-main"},
         {"stream": 2, "method": "GET", "path": "/v1/pushed",
          "url": "https://api.example.com/v1/pushed"}],
        [{"stream": 1, "status": 200, "contentType": "application/json", "body": main_body.decode()},
         {"stream": 2, "status": 200, "contentType": "application/json", "body": push_body.decode()}],
        validate_reqs=[("GET", "/v1/push-main")])


# ------------------------------------------- s13: PRIORITY 不产生幽灵 stream 上下文
def s13():
    body = b'{"phantom":0}'
    c = Conn(with_preface=True)
    # 从未承载请求的空闲 stream 99 上发 PRIORITY
    c.raw(frame(PRIORITY, 0, 99, struct.pack(">I", 0) + bytes([16])))
    c.headers(1, req_pairs("GET", "api.example.com", "/v1/no-phantom", []), end_stream=True)
    # 再补一个孤立的 CONTINUATION（没有前置 HEADERS），同样不该造出流
    c.raw(frame(CONTINUATION, END_HEADERS, 77, b"\x82"))
    s = Conn()
    s.headers(1, resp_pairs(200, [("content-type", "application/json"),
                                  ("content-length", str(len(body)))]))
    s.data(1, body, end_stream=True)
    add("priority_no_phantom", c, s,
        [{"stream": 1, "method": "GET", "path": "/v1/no-phantom",
          "url": "https://api.example.com/v1/no-phantom"}],
        [{"stream": 1, "status": 200, "contentType": "application/json", "body": body.decode()}],
        validate_stream=False)  # 故意含非法的孤立 CONTINUATION，h2 会拒绝，只测本实现健壮性


HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_JSON = os.path.join(HERE, "h2_fixtures.json")
DEFAULT_KT = os.path.join(
    HERE, "..", "src", "test", "java", "com", "agent", "use", "common", "network", "parser",
    "H2ConformanceFixtures.kt",
)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else None
    print("生成 HTTP/2 测试向量：")
    for fn in (s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13):
        fn()
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(FIXTURES, f, ensure_ascii=False, indent=1)
        print(f"\n共 {len(FIXTURES)} 组，JSON 副本已写入 {out}")
    else:
        print(f"\n共 {len(FIXTURES)} 组")

    kt = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_KT
    emit_kotlin(os.path.normpath(kt))
    print(f"Kotlin 夹具已写入 {os.path.normpath(kt)}")


if __name__ == "__main__":
    main()
