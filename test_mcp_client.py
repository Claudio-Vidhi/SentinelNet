# -*- coding: utf-8 -*-
"""Unit test per il parsing SSE del client MCP (preview)."""

import json
import unittest

import mcp_client


class TestParseSseLastData(unittest.TestCase):
    def test_single_event(self):
        text = 'data: {"jsonrpc":"2.0","id":2,"result":{}}\n\n'
        self.assertEqual(mcp_client.parse_sse_last_data(text),
                         '{"jsonrpc":"2.0","id":2,"result":{}}')

    def test_last_of_multiple_events(self):
        text = ('event: message\n'
                'data: {"n":1}\n\n'
                'data: {"n":2}\n\n')
        self.assertEqual(mcp_client.parse_sse_last_data(text), '{"n":2}')

    def test_ignores_comments_and_keepalive(self):
        text = (': keep-alive\n'
                'data: {"ok":true}\n\n')
        self.assertEqual(mcp_client.parse_sse_last_data(text), '{"ok":true}')

    def test_multiline_data_joined(self):
        text = 'data: {"a":1,\ndata: "b":2}\n\n'
        self.assertEqual(mcp_client.parse_sse_last_data(text), '{"a":1,\n"b":2}')

    def test_no_trailing_blank_line(self):
        text = 'data: {"x":1}'
        self.assertEqual(mcp_client.parse_sse_last_data(text), '{"x":1}')

    def test_empty(self):
        self.assertEqual(mcp_client.parse_sse_last_data(""), "")


class _FakeResponse:
    """Risposta requests.Response minimale, con iter_content() a chunk fissi."""

    def __init__(self, body: bytes, content_type="application/json", chunk_size=65536):
        self._body = body
        self.headers = {"Content-Type": content_type}
        self.encoding = "utf-8"
        self.apparent_encoding = "utf-8"
        self._chunk_size = chunk_size

    def iter_content(self, chunk_size=65536):
        step = chunk_size or self._chunk_size
        for i in range(0, len(self._body), step):
            yield self._body[i:i + step]


class TestResponseSizeCap(unittest.TestCase):
    def test_read_capped_under_limit_ok(self):
        body = json.dumps({"ok": True}).encode("utf-8")
        resp = _FakeResponse(body)
        self.assertEqual(mcp_client._read_capped(resp, max_bytes=1024), '{"ok": true}')

    def test_read_capped_over_limit_raises_clean_error(self):
        # Oversized body (well beyond the cap) must not be fully buffered in
        # memory: iteration should abort as soon as the cap is exceeded.
        oversized = b"x" * (2 * 1024 * 1024)
        resp = _FakeResponse(oversized, chunk_size=8192)
        with self.assertRaises(mcp_client.McpClientError) as ctx:
            mcp_client._read_capped(resp, max_bytes=1024 * 1024)
        self.assertIn("troppo grande", str(ctx.exception))

    def test_parse_response_oversized_json_body_raises(self):
        # Beyond the default 5 MB cap used by _parse_response.
        oversized = b'{"jsonrpc": "2.0", "id": 1, "result": "' + b"x" * (6 * 1024 * 1024) + b'"}'
        resp = _FakeResponse(oversized)
        with self.assertRaises(mcp_client.McpClientError):
            mcp_client._parse_response(resp)

    def test_parse_response_within_cap_still_parses(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode("utf-8")
        resp = _FakeResponse(body)
        data = mcp_client._parse_response(resp)
        self.assertEqual(data["id"], 1)


if __name__ == "__main__":
    unittest.main()
