"""Code Autopsy — interface web : autopsie d'un dépôt (dossier local, archive .zip ou démo)."""
from __future__ import annotations

import io
import json
import os
import secrets
import shutil
import zipfile

from flask import Flask, Response, jsonify, request

from autopsy import demo
from autopsy.analyzer import analyze_project

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("AUTOPSY_DATA", os.path.join(HERE, "data"))
ALLOW_PATHS = os.environ.get("AUTOPSY_ALLOW_PATHS", "1") != "0"   # analyse de dossiers locaux (outil local)
MAX_ZIP = 60 * 1024 * 1024
app = Flask(__name__, static_folder="static", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_ZIP
_cache: dict[str, dict] = {}


def _store(result: dict, src_root: str) -> dict:
    aid = secrets.token_hex(5)
    result["id"], result["src"] = aid, src_root
    os.makedirs(DATA, exist_ok=True)
    with open(os.path.join(DATA, f"{aid}.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False)
    _cache[aid] = result
    return result


def _load(aid: str) -> dict | None:
    if not aid.isalnum():
        return None
    if aid not in _cache:
        p = os.path.join(DATA, f"{aid}.json")
        if not os.path.exists(p):
            return None
        _cache[aid] = json.load(open(p, encoding="utf-8"))
    return _cache[aid]


def _public(r: dict) -> dict:
    return {k: v for k, v in r.items() if k not in ("src", "root")}


def safe_extract(data: bytes, dest: str) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        total = 0
        for info in z.infolist():
            total += info.file_size
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(os.path.realpath(dest) + os.sep) and target != os.path.realpath(dest):
                raise ValueError("Archive refusée : chemin hors du dossier (zip slip)")
            if total > 300 * 1024 * 1024 or len(z.infolist()) > 20000:
                raise ValueError("Archive trop volumineuse")
        z.extractall(dest)
    entries = [e for e in os.listdir(dest) if not e.startswith("__MACOSX")]
    if len(entries) == 1 and os.path.isdir(os.path.join(dest, entries[0])):
        return os.path.join(dest, entries[0])  # archive GitHub : un seul dossier racine
    return dest


@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.post("/api/analyze")
def analyze():
    os.makedirs(os.path.join(DATA, "src"), exist_ok=True)
    try:
        if "archive" in request.files:
            f = request.files["archive"]
            dest = os.path.join(DATA, "src", secrets.token_hex(5))
            os.makedirs(dest)
            root = safe_extract(f.read(), dest)
            name = os.path.splitext(f.filename or "archive")[0]
        else:
            body = request.get_json(silent=True) or {}
            if body.get("demo"):
                root = demo.build(os.path.join(DATA, "src", "patient-zero"))
                name = "patient-zero (démo)"
            else:
                if not ALLOW_PATHS:
                    return jsonify(error="L'analyse de dossiers locaux est désactivée sur ce serveur"), 403
                root = os.path.abspath(os.path.expanduser(str(body.get("path", "")).strip()))
                if not os.path.isdir(root):
                    return jsonify(error="Dossier introuvable"), 400
                name = None
    except (ValueError, zipfile.BadZipFile) as e:
        return jsonify(error=str(e) or "Archive invalide"), 400
    result = analyze_project(root, name)
    if not result["files"]:
        return jsonify(error="Aucun fichier source reconnu dans ce projet"), 400
    r = _store(result, root)
    return jsonify(id=r["id"], name=r["name"], summary=r["summary"])


@app.get("/api/analyses")
def analyses():
    out = []
    if os.path.isdir(DATA):
        for fn in sorted(os.listdir(DATA), key=lambda f: -os.path.getmtime(os.path.join(DATA, f))):
            if fn.endswith(".json"):
                r = _load(fn[:-5])
                if r:
                    out.append({"id": r["id"], "name": r["name"], "grade": r["summary"]["grade"], "health": r["summary"]["health"], "at": r["analyzed_at"]})
    return jsonify(out[:30])


@app.get("/api/analysis/<aid>")
def analysis(aid):
    r = _load(aid)
    return jsonify(_public(r)) if r else (jsonify(error="Analyse introuvable"), 404)


@app.get("/api/analysis/<aid>/file")
def source(aid):
    r = _load(aid)
    if not r:
        return jsonify(error="Analyse introuvable"), 404
    rel = request.args.get("path", "")
    f = next((x for x in r["files"] if x["path"] == rel), None)
    if not f:
        return jsonify(error="Fichier inconnu"), 404
    full = os.path.realpath(os.path.join(r["src"], rel))
    if not full.startswith(os.path.realpath(r["src"]) + os.sep) or not os.path.exists(full):
        return jsonify(error="Source plus disponible"), 410
    lines = open(full, encoding="utf-8", errors="replace").read().splitlines()
    dups = [d for d in r["duplicates"] if rel in (d["a"], d["b"])]
    return jsonify(file=f, lines=lines, duplicates=dups)


@app.get("/api/analysis/<aid>/report.md")
def report(aid):
    r = _load(aid)
    if not r:
        return jsonify(error="Analyse introuvable"), 404
    return Response(markdown_report(r), mimetype="text/markdown",
                    headers={"Content-Disposition": f'attachment; filename="autopsie-{r["name"].split()[0]}.md"'})


def markdown_report(r: dict) -> str:
    s = r["summary"]
    out = [f"# Rapport d'autopsie — {r['name']}", "", f"*Analyse du {r['analyzed_at']}*", "",
           f"**Note : {s['grade']} — {s['verdict']}** (santé {s['health']}/100)", "",
           "## Cause probable du décès", ""] + [f"{i}. {c}" for i, c in enumerate(s["causes"] or ["aucune pathologie majeure"], 1)] + [
           "", "## Constantes vitales", "", "| Mesure | Valeur |", "|---|---|",
           f"| Fichiers | {s['files']} |", f"| Lignes de code | {s['code']} |", f"| Fonctions | {s['functions']} |",
           f"| Complexité moyenne | {s['avg_cc']} |", f"| Indice de maintenabilité | {s['mi']} |", f"| Code dupliqué | {s['dup_ratio']:.1%} |",
           f"| Symptômes | {s['smells']} (critiques : {s['by_sev'].get('crit', 0)}) |", f"| Fonctions possiblement mortes | {s['dead']} |", ""]
    if r.get("git"):
        out += [f"| Commits analysés | {r['git']['commits']} |", ""]
    out += ["## Points chauds (complexité × fréquence de modification)", ""]
    out += [f"- `{h['path']}` — score {h['score']}, complexité {h['cc']}, churn {h['churn']}, corrections de bugs {h['fixes']}" for h in r["hotspots"][:8]]
    out += ["", "## Fonctions les plus complexes", ""]
    out += [f"- `{f['path']}:{f['start']}` **{f['name']}** — complexité {f['cc']}, {f['length']} lignes" for f in s["worst_functions"]]
    out += ["", "## Symptômes critiques", ""]
    out += [f"- `{f['path']}:{m['line']}` {m['msg']}" for f in r["files"] for m in f["smells"] if m["sev"] == "crit"] or ["- aucun"]
    return "\n".join(out) + "\n"


@app.delete("/api/analysis/<aid>")
def delete(aid):
    r = _load(aid)
    if not r:
        return jsonify(error="Analyse introuvable"), 404
    os.remove(os.path.join(DATA, f"{aid}.json"))
    srcdir = os.path.join(DATA, "src")
    if r["src"].startswith(srcdir + os.sep) and "patient-zero" not in r["src"]:
        shutil.rmtree(os.path.join(srcdir, os.path.relpath(r["src"], srcdir).split(os.sep)[0]), ignore_errors=True)
    _cache.pop(aid, None)
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5026)), debug=False)
