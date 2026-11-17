package com.agent.use.common.network.parser

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
        Case(
            name = "basic_get",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAAA0AQUAAAABgodBix1mXL5HTXQVch6fRI1juFiUpZP8SOaAf+4/eoeM6EMBZXB/U4sdddBiDSY9THRB6g==",
            inboundB64 = "AAAABAAAAAAAAAASAQQAAAABiF+LHXXQYg0mPUx0QepcgnAfAAA8AAEAAAABeyJjb2RlIjogMCwgInpwRGF0YSI6IHsiam9iTGlzdCI6IFt7ImpvYk5hbWUiOiAiQW5kcm9pZCJ9XX19",
            requests = listOf(
                ExpectedRequest(1, "GET", "https://api.example.com/v1/feed?tag=a+b", null),
            ),
            responses = listOf(
                ExpectedResponse(1, 200, "application/json", "{\"code\": 0, \"zpData\": {\"jobList\": [{\"jobName\": \"Android\"}]}}", null),
            ),
        ),
        Case(
            name = "post_split_data",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAAAvAQQAAAABg4dBi/Hjwv7nNWapch6fRI1jwOszHuu1BbGKDzGqX4sdddBiDSY9THRB6lyCaB8AAAcAAAAAAAF7InBob25lAAAhAAEAAAABIjogIjEzODAwMDAwMDAwIiwgImNvZGUiOiAiMTIzNCJ9",
            inboundB64 = "AAAABAAAAAAAAAASAQQAAAABiF+LHXXQYg0mPUx0QepcghO/AAAFAAAAAAABeyJjb2QAABYAAQAAAAFlIjogMCwgInRva2VuIjogImFiYyJ9",
            requests = listOf(
                ExpectedRequest(1, "POST", "https://www.zhipin.com/wapi/zpuser/login", "{\"phone\": \"13800000000\", \"code\": \"1234\"}"),
            ),
            responses = listOf(
                ExpectedResponse(1, 200, "application/json", "{\"code\": 0, \"token\": \"abc\"}", null),
            ),
        ),
        Case(
            name = "padded_priority",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAAAsAS0AAAADDQAAAADIgodBix1mXL5HTXQVch6fRIhjuFisckhZPwAAAAAAAAAAAAAAAAA=",
            inboundB64 = "AAAABAAAAAAAAAAaAQwAAAADB4hfix110GINJj1MdEHqXIIT3wAAAAAAAAAAACIACQAAAAMFeyJvayI6dHJ1ZSwicGFkZGluZ190ZXN0IjoxfQAAAAAA",
            requests = listOf(
                ExpectedRequest(3, "GET", "https://api.example.com/v1/padded", null),
            ),
            responses = listOf(
                ExpectedResponse(3, 200, "application/json", "{\"ok\":true,\"padding_test\":1}", null),
            ),
        ),
        Case(
            name = "continuation_split",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAAB4AQEAAAAFgodBix1mXL5HTXQVch6fRItjuFgh6kmqtGkx6kCL8rJsGQq1Y/VBxyf/lQXfv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv3AAB4CQAAAAAF79+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fvAAB4CQAAAAAF379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fAAB4CQAAAAAFv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/AAB4CQAAAAAFfv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+AAB4CQAAAAAF/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379AABwCQQAAAAF+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/w==",
            inboundB64 = "AAAABAAAAAAAAABkAQAAAAAFiF+LHXXQYg0mPUx0Qepcggg/QIvysmwZCrVj9UHHJ/+VBd+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fgAAZAkAAAAABf379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fsAAGQJAAAAAAX379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fvAABkCQAAAAAF379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fvwAAZAkAAAAABX79+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv0AAGQJAAAAAAX79+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv3AABkCQAAAAAF79+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv3wAAZAkAAAAABb9+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv379+/fv34AABYJBAAAAAX9+/fv379+/fv379+/fv379+/fv37/AAAKAAEAAAAFeyJjb250IjoxfQ==",
            requests = listOf(
                ExpectedRequest(5, "GET", "https://api.example.com/v1/continuation", null),
            ),
            responses = listOf(
                ExpectedResponse(5, 200, "application/json", "{\"cont\":1}", "x-trace-payload"),
            ),
        ),
        Case(
            name = "response_trailers",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAAAZAQUAAAAHg4dBix1mXL5HTXQVch6fRIhjuFhNgzUFsw==",
            inboundB64 = "AAAABAAAAAAAAAAOAQQAAAAHiF+LHXXQYg0mPUx0QeoAABAAAAAAAAd7InRyYWlsZXIiOnRydWV9AAARAQUAAAAHQIjysScpOqLaf4aQo5Iyll8=",
            requests = listOf(
                ExpectedRequest(7, "POST", "https://api.example.com/v1/trailer", null),
            ),
            responses = listOf(
                ExpectedResponse(7, 200, "application/json", "{\"trailer\":true}", "x-checksum"),
            ),
        ),
        Case(
            name = "dynamic_table_reuse",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAABLAQUAAAABgodBix1mXL5HTXQVch6fRIxjuFgyS0o/yscxYA+QQIfysgqEGPV/o927du3bt27du3bt27du3bt27du3bt27du3bt27du3bt27duAAATAQUAAAADgofARIxjuFgyS0o/yscxYBeQvwAAFgEFAAAABT/hAYKHwUSMY7hYMktKP8rHMWBnkMA=",
            inboundB64 = "AAAABAAAAAAAAAA/AQQAAAABiF+LHXXQYg0mPUx0Qepcggh/QIfysgqEGPV/o927du3bt27du3bt27du3bt27du3bt27du3bt27du3bt27duAAALAAEAAAABeyJwYWdlIjogMX0AAAQBBAAAAAOIwL++AAALAAEAAAADeyJwYWdlIjogMn0AAAcBBAAAAAU/4QGIwL++AAALAAEAAAAFeyJwYWdlIjogM30=",
            requests = listOf(
                ExpectedRequest(1, "GET", "https://api.example.com/v1/items?page=1", null),
                ExpectedRequest(3, "GET", "https://api.example.com/v1/items?page=2", null),
                ExpectedRequest(5, "GET", "https://api.example.com/v1/items?page=3", null),
            ),
            responses = listOf(
                ExpectedResponse(1, 200, "application/json", "{\"page\": 1}", null),
                ExpectedResponse(3, 200, "application/json", "{\"page\": 2}", null),
                ExpectedResponse(5, 200, "application/json", "{\"page\": 3}", null),
            ),
        ),
        Case(
            name = "rst_stream",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAAAYAQUAAAAJgodBix1mXL5HTXQVch6fRIdjuFgcZ7E/",
            inboundB64 = "AAAABAAAAAAAAAAKAQQAAAAJiF+HSXyliugZqgAADAAAAAAACXBhcnRpYWwtYm9keQAABAMAAAAACQAAAAg=",
            requests = listOf(
                ExpectedRequest(9, "GET", "https://api.example.com/v1/abort", null),
            ),
            responses = listOf(
                ExpectedResponse(9, 200, "text/plain", "partial-body", null),
            ),
        ),
        Case(
            name = "informational_100",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAAAYAQUAAAALgodBix1mXL5HTXQVch6fRIdjuFgo7KPX",
            inboundB64 = "AAAABAAAAAAAAAAEAQQAAAALSIIIAQAAEgEEAAAAC4hfix110GINJj1MdEHqXIILPwAADQABAAAAC3siYWZ0ZXIiOjEwM30=",
            requests = listOf(
                ExpectedRequest(11, "GET", "https://api.example.com/v1/early", null),
            ),
            responses = listOf(
                ExpectedResponse(11, 200, "application/json", "{\"after\":103}", null),
            ),
        ),
        Case(
            name = "gzip_response",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAAAXAQUAAAANgodBix1mXL5HTXQVch6fRIZjuFib2as=",
            inboundB64 = "AAAABAAAAAAAAAATAQQAAAANiF+LHXXQYg0mPUx0Qepag5vZqwAACgAAAAAADR+LCACIYPxqAv8AAFQAAQAAAA0VyjsKgDAABNGrLKm3cP3Hq4hlkBSCaGwU7+5aDvOesN55DxPKcSUi5JK20zlXhIiaaIiW6IieGIiRiF7/9peBLGQiGxnJSmaKy/sBgeGS5l8AAAA=",
            requests = listOf(
                ExpectedRequest(13, "GET", "https://api.example.com/v1/gzip", null),
            ),
            responses = listOf(
                ExpectedResponse(13, 200, "application/json", "{\"gzip\": true, \"items\": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]}", null),
            ),
        ),
        Case(
            name = "midstream_no_preface",
            outboundB64 = "AAAABAAAAAAAAAAXAQUAAAABgodBix1mXL5HTXQVch6fRIZjuFik0n8=",
            inboundB64 = "AAAABAAAAAAAAAARAQQAAAABiF+LHXXQYg0mPUx0QepcgX8AAAkAAQAAAAF7Im1pZCI6MX0=",
            requests = listOf(
                ExpectedRequest(1, "GET", "https://api.example.com/v1/mid", null),
            ),
            responses = listOf(
                ExpectedResponse(1, 200, "application/json", "{\"mid\":1}", null),
            ),
        ),
        Case(
            name = "goaway_truncated",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAAAZAQUAAAABgodBix1mXL5HTXQVch6fRIhjuFiY4/A/Xw==",
            inboundB64 = "AAAABAAAAAAAAAAKAQQAAAABiF+HSXyliugZqgAAFgAAAAAAAXBhcnRpYWwtYm9keS10cnVuY2F0ZWQAAAgHAAAAAAAAAAAAAAAAAA==",
            requests = listOf(
                ExpectedRequest(1, "GET", "https://api.example.com/v1/goaway", null),
            ),
            responses = listOf(
                ExpectedResponse(1, 200, "text/plain", "partial-body-truncated", null),
            ),
        ),
        Case(
            name = "push_promise",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAAAbAQUAAAABgodBix1mXL5HTXQVch6fRIpjuFiu1E61IzVf",
            inboundB64 = "AAAABAAAAAAAAAAdBQQAAAABAAAAAoKHQYsdZly+R010FXIen0SIY7hYrtROWT8AABIBBAAAAAGIX4sdddBiDSY9THRB6lyCC38AAA8AAQAAAAF7InB1c2giOiJtYWluIn0AAAYBBAAAAAKIv1yCC58AABAAAQAAAAJ7InB1c2giOiJhc3NldCJ9",
            requests = listOf(
                ExpectedRequest(1, "GET", "https://api.example.com/v1/push-main", null),
                ExpectedRequest(2, "GET", "https://api.example.com/v1/pushed", null),
            ),
            responses = listOf(
                ExpectedResponse(1, 200, "application/json", "{\"push\":\"main\"}", null),
                ExpectedResponse(2, 200, "application/json", "{\"push\":\"asset\"}", null),
            ),
        ),
        Case(
            name = "priority_no_phantom",
            outboundB64 = "UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAABAAAAAAAAAAFAgAAAABjAAAAABAAABsBBQAAAAGCh0GLHWZcvkdNdBVyHp9EimO4WKjrVzjqSekAAAEJBAAAAE2C",
            inboundB64 = "AAAABAAAAAAAAAASAQQAAAABiF+LHXXQYg0mPUx0Qepcggs/AAANAAEAAAABeyJwaGFudG9tIjowfQ==",
            requests = listOf(
                ExpectedRequest(1, "GET", "https://api.example.com/v1/no-phantom", null),
            ),
            responses = listOf(
                ExpectedResponse(1, 200, "application/json", "{\"phantom\":0}", null),
            ),
        ),
    )
}
