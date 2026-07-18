# -*- coding: utf-8 -*-
"""Unit test per il parsing SSE del client MCP (preview)."""

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


if __name__ == "__main__":
    unittest.main()
