import io, json, os, sys, zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from autopsy import analyzer, demo

PY = '''import os
import json
def simple(a):
    return a + 1
def branchy(x, y):
    if x and y:
        for i in range(3):
            if i:
                pass
    elif x:
        pass
    return [i for i in range(5) if i]
def bad(a=[]):
    try:
        eval("1")
    except:
        pass
API_KEY = "abcdefgh12345"
'''

def test_python_metrics():
    fns, smells, _ = analyzer.analyze_python(PY, "m.py")
    by = {f["name"]: f for f in fns}
    assert by["simple"]["cc"] == 1
    # if + and + for + if + elif + comprehension(1 + 1 if) = 1 + 7
    assert by["branchy"]["cc"] == 8
    assert by["branchy"]["nest"] == 3
    kinds = {s["kind"] for s in smells}
    assert {"mutable-default", "bare-except", "swallowed", "eval", "unused-import"} <= kinds

def test_file_level_secret(tmp_path):
    p = tmp_path / "m.py"; p.write_text(PY)
    r = analyzer.analyze_file(str(p), "m.py")
    assert any(s["kind"] == "secret" for s in r["smells"])
    assert 0 <= r["mi"] <= 100

def test_js_functions():
    src = "function a(x, y) {\n  if (x && y) { return 1 }\n  return x ? 2 : 3\n}\nconst b = async (z) => {\n  el.innerHTML = z\n}\n"
    fns, smells, _ = analyzer.analyze_braces(src, "JavaScript")
    by = {f["name"]: f for f in fns}
    assert by["a"]["cc"] == 4 and by["a"]["params"] == 2 and "b" in by
    assert any(s["kind"] == "xss" and s["sev"] == "warn" for s in smells)

def test_duplicates():
    block = [f"x{i} = compute(x{i-1}, {i})" for i in range(1, 12)]
    dups = analyzer.find_duplicates({"a.py": ["# a"] + block, "b.py": ["y = 0", "z = 1"] + block})
    assert dups and dups[0]["lines"] == 11

def test_demo_project_with_git(tmp_path):
    root = demo.build(str(tmp_path / "pz"))
    r = analyzer.analyze_project(root, "pz")
    s = r["summary"]
    assert r["git"]["commits"] == len(demo.HISTORY) and len(r["git"]["authors"]) == 4
    assert r["hotspots"][0]["path"] == "shop/orders.py"
    assert s["grade"] in "DE" and s["dup_blocks"] >= 1 and s["by_sev"]["crit"] >= 5
    assert any(c["a"] == "shop/invoices.py" for c in r["git"]["coupling"])

def test_api(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPSY_DATA", str(tmp_path / "data"))
    import importlib, app as appmod
    importlib.reload(appmod)
    c = appmod.app.test_client()
    r = c.post("/api/analyze", json={"demo": True}).get_json()
    aid = r["id"]
    assert c.get(f"/api/analysis/{aid}").get_json()["summary"]["files"] == 6
    f = c.get(f"/api/analysis/{aid}/file?path=shop/orders.py").get_json()
    assert f["lines"][0].startswith("import")
    assert c.get(f"/api/analysis/{aid}/file?path=../../etc/passwd").status_code == 404
    assert b"Rapport d'autopsie" in c.get(f"/api/analysis/{aid}/report.md").data
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("proj-main/a.py", "def f(x):\n    return x\n")
    r = c.post("/api/analyze", data={"archive": (io.BytesIO(buf.getvalue()), "proj.zip")}, content_type="multipart/form-data").get_json()
    assert r["summary"]["files"] == 1
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../evil.py", "x=1")
    assert c.post("/api/analyze", data={"archive": (io.BytesIO(evil.getvalue()), "e.zip")}, content_type="multipart/form-data").status_code == 400
    assert c.delete(f"/api/analysis/{aid}").get_json()["ok"]
