"""Dashboard tests, with emphasis on the access controls.

A localhost server that can spend your API budget is worth testing like one:
any page open in the user's browser can reach 127.0.0.1.
"""

import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from driftguard.ui.server import serve


@pytest.fixture(scope="module")
def ui():
    httpd, url = serve(port=0, open_browser=False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    token = url.split("token=")[1]
    base = f"http://127.0.0.1:{httpd.server_port}"
    yield base, token
    httpd.shutdown()


def _get(base, path, token=None, origin=None):
    req = urllib.request.Request(base + path)
    if token:
        req.add_header("X-Driftguard-Token", token)
    if origin:
        req.add_header("Origin", origin)
    return urllib.request.urlopen(req, timeout=5)


def test_api_requires_a_token(ui):
    base, _ = ui
    with pytest.raises(urllib.error.HTTPError) as e:
        _get(base, "/api/state")
    assert e.value.code == 403


def test_wrong_token_rejected(ui):
    base, _ = ui
    with pytest.raises(urllib.error.HTTPError) as e:
        _get(base, "/api/state", token="not-the-token")
    assert e.value.code == 403


def test_foreign_origin_rejected_even_with_a_valid_token(ui):
    """Defence in depth: a leaked token must not be usable from another page."""
    base, token = ui
    with pytest.raises(urllib.error.HTTPError) as e:
        _get(base, "/api/state", token=token, origin="https://evil.test")
    assert e.value.code == 403


def test_valid_token_works(ui):
    base, token = ui
    data = json.loads(_get(base, "/api/state", token=token).read())
    assert any(p["name"] == "prompt_injection" for p in data["packs"])
    assert any(p["kind"] == "benign" for p in data["packs"])


def test_index_requires_token_too(ui):
    base, token = ui
    with pytest.raises(urllib.error.HTTPError):
        _get(base, "/")
    body = _get(base, f"/?token={token}").read().decode()
    assert "<title>driftguard</title>" in body
    assert "__TOKEN__" not in body, "token placeholder was not substituted"
    assert token in body


def test_no_external_resources_in_the_page(ui):
    """The dashboard must work offline and leak nothing to a CDN."""
    base, token = ui
    body = _get(base, f"/?token={token}").read().decode()
    for marker in ("http://", "https://", "//cdn", "<script src"):
        if marker in ("http://", "https://"):
            # allowed only inside placeholder text, not as a resource URL
            assert 'src="http' not in body and 'href="http' not in body
        else:
            assert marker not in body


def test_run_endpoint_executes_and_reports(ui):
    """End to end through the HTTP API using the offline mock provider."""
    base, token = ui
    payload = json.dumps(
        {"models": ["echo:mock"], "packs": ["tool_abuse"], "samples": 2}
    ).encode()
    req = urllib.request.Request(base + "/api/run", data=payload, method="POST")
    req.add_header("X-Driftguard-Token", token)
    req.add_header("Content-Type", "application/json")
    run_id = json.loads(urllib.request.urlopen(req, timeout=5).read())["id"]

    for _ in range(100):
        state = json.loads(_get(base, f"/api/run/{run_id}", token=token).read())
        if state["status"] != "running":
            break
        time.sleep(0.1)

    assert state["status"] == "done", state.get("error")
    model = state["models"][0]
    cases = state["results"][model]["cases"]
    assert cases and all("examples" in c for c in cases)
    assert "asr" in state["results"][model]["metrics"]


def test_unknown_run_is_404(ui):
    base, token = ui
    with pytest.raises(urllib.error.HTTPError) as e:
        _get(base, "/api/run/doesnotexist", token=token)
    assert e.value.code == 404
