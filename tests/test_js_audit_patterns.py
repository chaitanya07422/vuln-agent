from vuln_agent.agents.js_audit import PATTERNS


SAMPLE = r'''
const f=await fetch("/api/uploads/request-url",{method:"POST",body:JSON.stringify({name:m.name,size:m.size,contentType:m.type||"application/octet-stream"})});
await c(m,w.uploadURL); const objectPath = w.objectPath;
accept:".pdf,.doc,.docx"
R.resumePath&&r.jsxs("a",{href:R.resumePath,target:"_blank"
"/objects/uploads/"
'''

# Mirrors live netopsys.in minified shapes (no /objects/uploads literal)
LIVE_LIKE = (
    'fetch("/api/uploads/request-url",{method:"POST",headers:{"Content-Type":"application/json"},'
    'body:JSON.stringify({name:m.name,size:m.size,contentType:m.type||"application/octet-stream"})});'
    'return{method:"PUT",url:(await f.json()).uploadURL,headers:{"Content-Type":m.type}};'
    'w.objectPath;'
    'accept:".pdf,.doc,.docx",onChange:L;'
    'R.resumePath&&r.jsxs("a",{href:R.resumePath,target:"_blank",rel:"noopener noreferrer"'
)


def test_patterns_match_netopsys_like_bundle():
    ids = {p["id"] for p in PATTERNS if p["regex"].search(SAMPLE)}
    assert "open_href_resume" in ids
    assert "upload_passthrough_ctype" in ids
    assert "client_only_accept" in ids
    assert "objects_uploads_path" in ids


def test_patterns_match_live_minified_shapes():
    ids = {p["id"] for p in PATTERNS if p["regex"].search(LIVE_LIKE)}
    assert ids >= {
        "open_href_resume",
        "upload_passthrough_ctype",
        "client_only_accept",
        "objects_uploads_path",
    }
