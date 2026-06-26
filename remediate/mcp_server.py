#!/usr/bin/env python3
"""MCP server exposing deph's remediation tools over stdio.

The model-agnostic investigation surface: add this as an MCP server in any client
(Claude Desktop, Cursor, Continue, your own) and investigate a report with whatever
model that client uses. No provider config, no key here — the client brings the model.

  python3 mcp_server.py path/to/deph-report.json
  # or: DEPH_REPORT=path/to/report.json python3 mcp_server.py

Speaks the MCP JSON-RPC subset clients need: initialize, tools/list, tools/call.
Stdlib only.
"""
import json
import os
import sys

import tools as T

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "deph-remediate", "version": "0.1.0"}


def _load_report():
    path = (sys.argv[1] if len(sys.argv) > 1 else None) or os.environ.get("DEPH_REPORT")
    if not path:
        sys.stderr.write("usage: mcp_server.py <deph-report.json>  (or set DEPH_REPORT)\n")
        sys.exit(2)
    with open(path) as f:
        return json.load(f)


def _result(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def handle(req, report):
    method, rid = req.get("method"), req.get("id")
    if method == "initialize":
        return _result(rid, {"protocolVersion": PROTOCOL_VERSION,
                             "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO})
    if method in ("notifications/initialized", "initialized"):
        return None  # notification, no response
    if method == "tools/list":
        return _result(rid, {"tools": [
            {"name": t["name"], "description": t["description"], "inputSchema": t["schema"]}
            for t in T.tool_list()
        ]})
    if method == "tools/call":
        params = req.get("params", {})
        name, args = params.get("name"), params.get("arguments", {})
        try:
            out = T.dispatch(name, args, report)
            return _result(rid, {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]})
        except KeyError:
            return _error(rid, -32601, f"unknown tool: {name}")
        except Exception as e:
            return _result(rid, {"isError": True,
                                 "content": [{"type": "text", "text": f"error: {e}"}]})
    if rid is None:
        return None  # unknown notification
    return _error(rid, -32601, f"method not found: {method}")


def main():
    report = _load_report()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(req, report)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
