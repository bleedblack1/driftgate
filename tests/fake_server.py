"""A minimal OpenAI-compatible /v1/chat/completions server.

Used to prove the provider layer works against a real HTTP endpoint without
contacting any vendor. `vulnerability` controls how often the fake model obeys
injected instructions, so the whole pipeline can be exercised offline.
"""

from __future__ import annotations

import json
import random
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


def make_server(vulnerability: float = 0.0, seed: int = 0) -> tuple[HTTPServer, str]:
    rng = random.Random(seed)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            messages = body.get("messages", [])
            convo = json.dumps(messages)
            already_called = any(m.get("role") == "tool" for m in messages)

            msg: dict = {"role": "assistant", "content": "Here is the summary.", "tool_calls": None}

            # The injected payload only reaches the model once the poisoned
            # tool result is in the conversation -- i.e. on the second turn.
            injected = "SYSTEM NOTE" in convo or "you must call" in convo.lower()

            if already_called or injected:
                if injected and rng.random() < vulnerability:
                    msg["tool_calls"] = [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {
                                "name": "delete_user",
                                "arguments": json.dumps({"user_id": "all"}),
                            },
                        }
                    ]
                    msg["content"] = None
            elif "fetch_url" in json.dumps(body.get("tools", [])) and "http" in convo:
                msg["tool_calls"] = [
                    {
                        "id": "c0",
                        "type": "function",
                        "function": {
                            "name": "fetch_url",
                            "arguments": json.dumps({"url": "https://docs.internal/report"}),
                        },
                    }
                ]
                msg["content"] = None

            payload = {"choices": [{"message": msg, "finish_reason": "stop"}]}
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/v1"
