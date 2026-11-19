"""Code Autopsy — moteur d'analyse statique + historique Git.

Python : analyse exacte via le module `ast`.
JS/TS, C/C++, Java, Go, PHP, Rust… : analyse heuristique (détection de fonctions par
regex + appariement des accolades, comptage des points de décision).
"""
from __future__ import annotations

import ast
import hashlib
import math
import os
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone

LANGS = {".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
         ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++", ".java": "Java", ".go": "Go", ".php": "PHP", ".rs": "Rust", ".cs": "C#",
         ".rb": "Ruby", ".sh": "Shell", ".kt": "Kotlin", ".swift": "Swift"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next", "target", "vendor", ".idea", ".vscode", "coverage", ".pytest_cache", "site-packages"}
MAX_FILE = 400_000
LIMITS = {"fn_len": 50, "params": 5, "cc_warn": 10, "cc_crit": 20, "nest": 4}

SECRET_RE = re.compile(r"""(?i)(?<![a-z])(pass(word|wd)?|secret|api[_-]?key|token|private[_-]?key|access[_-]?key)(?![a-z])["']?\s*[:=]\s*["'][^"'\s]{8,}["']""")
AWS_RE = re.compile(r"AKIA[0-9A-Z]{16}")
TODO_RE = re.compile(r"(#|//|/\*|\*)\s*(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)", re.I)
SEV = {"info": 1, "warn": 3, "crit": 8}


def smell(line, kind, sev, msg, fn=None):
    return {"line": line, "kind": kind, "sev": sev, "msg": msg, "fn": fn}


# ───────────────────────── Python (AST) ─────────────────────────
class _PyFn(ast.NodeVisitor):
    DECISIONS = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler, ast.Assert, ast.comprehension)

    def __init__(self):
        self.cc, self.depth, self.max_depth, self.elifs = 1, 0, 0, set()

    def generic_visit(self, node):
        if isinstance(node, self.DECISIONS):
            self.cc += 1 + (len(node.ifs) if isinstance(node, ast.comprehension) else 0)
        elif isinstance(node, ast.BoolOp):
            self.cc += len(node.values) - 1
        elif hasattr(ast, "match_case") and isinstance(node, ast.match_case):
            self.cc += 1
        if isinstance(node, ast.If) and len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
            self.elifs.add(id(node.orelse[0]))  # un elif reste au même niveau
        nests = isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)) and id(node) not in self.elifs
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return  # fonctions imbriquées : comptées séparément
        if nests:
            self.depth += 1
            self.max_depth = max(self.max_depth, self.depth)
        super().generic_visit(node)
        if nests:
            self.depth -= 1


def analyze_python(src: str, rel: str):
    tree = ast.parse(src)
    fns, smells = [], []
    lines = src.splitlines()
    imported, used = {}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            base = node
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name):
                used.add(base.id)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            v = _PyFn()
            v._root = node
            for child in ast.iter_child_nodes(node):
                v.visit(child)
            end = getattr(node, "end_lineno", node.lineno)
            a = node.args
            params = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs if x.arg not in ("self", "cls")] + ([a.vararg.arg] if a.vararg else []) + ([a.kwarg.arg] if a.kwarg else [])
            fn = {"name": node.name, "start": node.lineno, "end": end, "length": end - node.lineno + 1, "cc": v.cc, "params": len(params), "nest": v.max_depth,
                  "decorated": bool(node.decorator_list)}
            fns.append(fn)
            for d in a.defaults + a.kw_defaults:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)) or (isinstance(d, ast.Call) and getattr(d.func, "id", "") in ("list", "dict", "set")):
                    smells.append(smell(node.lineno, "mutable-default", "warn", f"« {node.name} » a un argument par défaut mutable (partagé entre les appels)", node.name))
        elif isinstance(node, ast.ExceptHandler):
            if node.type is None:
                smells.append(smell(node.lineno, "bare-except", "warn", "except: nu — attrape aussi KeyboardInterrupt et SystemExit"))
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                smells.append(smell(node.lineno, "swallowed", "warn", "Exception avalée silencieusement (except … : pass)"))
        elif isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
            full = ast.unparse(node.func) if hasattr(ast, "unparse") else name
            if name in ("eval", "exec") and isinstance(node.func, ast.Name):
                smells.append(smell(node.lineno, "eval", "crit", f"{name}() exécute du code arbitraire"))
            if full in ("os.system", "os.popen"):
                smells.append(smell(node.lineno, "shell", "crit", f"{full}() — injection de commande possible"))
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                smells.append(smell(node.lineno, "shell", "crit", f"{full}(shell=True) — injection de commande possible"))
            if full in ("pickle.loads", "pickle.load", "marshal.loads"):
                smells.append(smell(node.lineno, "deserialize", "crit", f"{full}() sur des données non fiables = exécution de code"))
            if full == "yaml.load" and not any(k.arg == "Loader" for k in node.keywords):
                smells.append(smell(node.lineno, "deserialize", "warn", "yaml.load sans Loader — préférer yaml.safe_load"))
            if any(k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False for k in node.keywords):
                smells.append(smell(node.lineno, "tls", "crit", "verify=False — vérification TLS désactivée"))
            if full in ("hashlib.md5", "hashlib.sha1"):
                smells.append(smell(node.lineno, "weak-hash", "info", f"{full} — faible pour un usage cryptographique"))
        elif isinstance(node, ast.Compare):
            for op, comp in zip(node.ops, node.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comp, ast.Constant) and comp.value is None:
                    smells.append(smell(node.lineno, "none-compare", "info", "Comparaison à None avec == (utiliser « is None »)"))
        elif isinstance(node, ast.ImportFrom):
            for al in node.names:
                if al.name == "*":
                    smells.append(smell(node.lineno, "star-import", "warn", f"from {node.module} import * — pollue l'espace de noms"))
                else:
                    imported[al.asname or al.name] = node.lineno
        elif isinstance(node, ast.Import):
            for al in node.names:
                imported[(al.asname or al.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.Global):
            smells.append(smell(node.lineno, "global", "info", f"global {', '.join(node.names)} — état partagé mutable"))
    if not rel.endswith("__init__.py"):
        all_names = re.findall(r"__all__", src)
        for name, ln in imported.items():
            if name not in used and not all_names and name != "annotations":
                smells.append(smell(ln, "unused-import", "info", f"Import inutilisé : {name}"))
    comments = sum(1 for ln in lines if ln.strip().startswith("#"))
    doc = sum((getattr(n, "end_lineno", 0) or 0) - n.lineno + 1 for n in ast.walk(tree) if isinstance(n, ast.Expr) and isinstance(getattr(n, "value", None), ast.Constant) and isinstance(n.value.value, str))
    return fns, smells, comments + doc


# ─────────────────── Langages à accolades (heuristique) ───────────────────
JS_FN = [re.compile(r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)"),
         re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*)?\(([^()]*)\)\s*(?:=>)?"),
         re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>"),
         re.compile(r"^\s*(?:async\s+|static\s+|get\s+|set\s+)*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{")]
C_FN = [re.compile(r"^\s*(?:[\w:<>\*&,\s]+?)\s+\**([A-Za-z_][\w:~]*)\s*\(([^;{}]*)\)\s*(?:const\s*)?(?:noexcept\s*)?(?:->\s*[\w:<>]+\s*)?\{?\s*$"),
        re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)"),
        re.compile(r"^\s*(?:pub\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)"),
        re.compile(r"^\s*(?:public|private|protected)?\s*(?:static\s+)?function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")]
KEYWORDS_NOT_FN = {"if", "for", "while", "switch", "catch", "return", "sizeof", "else", "do", "with", "typeof", "new", "function", "constructor"}
DECISION_RE = re.compile(r"\b(if|for|while|case|catch|elif|foreach)\b|&&|\|\||\?\?|(?<![?.])\?(?![.?:])")


def _strip_strings(line: str) -> str:
    line = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`', '""', line)
    return re.sub(r"//.*$", "", line)


def analyze_braces(src: str, lang: str):
    lines = src.splitlines()
    clean = [_strip_strings(ln) for ln in lines]
    pats = JS_FN if lang in ("JavaScript", "TypeScript") else C_FN
    fns, smells, comments = [], [], 0
    in_block = False
    for ln in lines:
        s = ln.strip()
        if in_block or s.startswith("/*"):
            comments += 1
            in_block = "*/" not in s
        elif s.startswith("//") or s.startswith("#") and lang == "Shell":
            comments += 1
    i = 0
    while i < len(clean):
        m = None
        for p in pats:
            m = p.search(clean[i])
            if m:
                break
        if m and m.group(1) not in KEYWORDS_NOT_FN:
            j, depth, opened = i, 0, False
            while j < len(clean) and j < i + 2000:
                for ch in clean[j]:
                    if ch == "{":
                        depth += 1
                        opened = True
                    elif ch == "}":
                        depth -= 1
                if opened and depth <= 0:
                    break
                if not opened and j > i + 2:
                    break
                j += 1
            if opened:
                body = clean[i:j + 1]
                cc = 1 + sum(len(DECISION_RE.findall(b)) for b in body)
                d, mx = 0, 0
                for b in body:
                    for ch in b:
                        if ch == "{":
                            d += 1
                            mx = max(mx, d)
                        elif ch == "}":
                            d -= 1
                params = len([p for p in m.group(2).split(",") if p.strip() and p.strip() != "void"]) if m.lastindex and m.lastindex >= 2 else 0
                fns.append({"name": m.group(1), "start": i + 1, "end": j + 1, "length": j - i + 1, "cc": cc, "params": params, "nest": max(0, mx - 1), "decorated": False})
                # les fonctions imbriquées sont aussi détectées : on continue à la ligne suivante
        i += 1
    js = lang in ("JavaScript", "TypeScript")
    for n, (raw, c) in enumerate(zip(lines, clean), 1):
        if re.search(r"\beval\s*\(|new\s+Function\s*\(", c):
            smells.append(smell(n, "eval", "crit", "eval / new Function — exécution de code arbitraire"))
        if js and re.search(r"\.innerHTML\s*\+?=(?!=)", c) and not re.search(r"innerHTML\s*=\s*[\"'`]{2}\s*;?\s*$", c):
            dyn = re.search(r"innerHTML\s*\+?=\s*(?:[A-Za-z_$]|.*(?:\$\{|\+\s*[A-Za-z_$]))", raw) and "esc(" not in raw and "escape" not in raw
            smells.append(smell(n, "xss", "warn" if dyn else "info", "innerHTML avec données non échappées (XSS)" if dyn else "innerHTML — vérifier que tout est échappé"))
        if js and re.search(r"document\.write\s*\(", c):
            smells.append(smell(n, "xss", "warn", "document.write — dangereux et bloquant"))
        if js and re.search(r"[^=!<>]==[^=]|!=[^=]", c):
            smells.append(smell(n, "loose-eq", "info", "Égalité faible (== / !=) — préférer === / !=="))
        if js and re.search(r"\bvar\s", c):
            smells.append(smell(n, "var", "info", "var — préférer let/const (portée de bloc)"))
        if js and re.search(r"console\.log\(", c):
            smells.append(smell(n, "debug", "info", "console.log oublié ?"))
        m = re.search(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(", c) if lang in ("C", "C++") else None
        if m:
            smells.append(smell(n, "overflow", "warn" if "sprintf" in m.group(1) else "crit", f"{m.group(1)}() — pas de borne de taille, débordement de tampon possible"))
        if lang in ("C", "C++", "PHP") and re.search(r"\b(system|popen|shell_exec|exec)\s*\(", c):
            smells.append(smell(n, "shell", "crit", "Exécution de commande shell"))
        if re.search(r"catch\s*\([^)]*\)\s*\{\s*\}", c):
            smells.append(smell(n, "swallowed", "warn", "Bloc catch vide — erreur avalée"))
    return fns, smells, comments


# ───────────────────────── Fichier ─────────────────────────
def halstead_volume(src: str) -> float:
    toks = re.findall(r"[A-Za-z_]\w*|\d+\.?\d*|==|!=|<=|>=|&&|\|\||[-+*/%=<>!&|^~?:;,.(){}\[\]]", src)
    n = len(set(toks)) or 1
    return len(toks) * math.log2(max(2, n))


def analyze_file(path: str, rel: str) -> dict | None:
    ext = os.path.splitext(path)[1].lower()
    lang = LANGS.get(ext)
    if not lang:
        return None
    try:
        if os.path.getsize(path) > MAX_FILE:
            return None
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    lines = src.splitlines()
    blank = sum(1 for ln in lines if not ln.strip())
    parse_error = None
    if lang == "Python":
        try:
            fns, smells, comments = analyze_python(src, rel)
        except SyntaxError as e:
            fns, smells, comments, parse_error = [], [smell(e.lineno or 1, "syntax", "crit", f"Erreur de syntaxe : {e.msg}")], 0, e.msg
    elif lang == "Shell":
        fns, smells, comments = [], [], sum(1 for ln in lines if ln.strip().startswith("#"))
    else:
        fns, smells, comments = analyze_braces(src, lang)
    for n, ln in enumerate(lines, 1):
        if SECRET_RE.search(ln) or AWS_RE.search(ln):
            smells.append(smell(n, "secret", "crit", "Secret / mot de passe écrit en dur dans le code"))
        m = TODO_RE.search(ln)
        if m:
            smells.append(smell(n, "todo", "info", f"{m.group(2).upper()} : {m.group(3).strip()[:80]}"))
    for f in fns:
        if f["length"] > LIMITS["fn_len"]:
            smells.append(smell(f["start"], "long-function", "crit" if f["length"] > 2 * LIMITS["fn_len"] else "warn", f"« {f['name']} » fait {f['length']} lignes", f["name"]))
        if f["cc"] > LIMITS["cc_warn"]:
            smells.append(smell(f["start"], "complexity", "crit" if f["cc"] > LIMITS["cc_crit"] else "warn", f"« {f['name']} » : complexité cyclomatique {f['cc']}", f["name"]))
        if f["params"] > LIMITS["params"]:
            smells.append(smell(f["start"], "params", "warn", f"« {f['name']} » prend {f['params']} paramètres", f["name"]))
        if f["nest"] > LIMITS["nest"]:
            smells.append(smell(f["start"], "nesting", "warn", f"« {f['name']} » : imbrication de profondeur {f['nest']}", f["name"]))
    code = max(0, len(lines) - blank - comments)
    cc_total = sum(f["cc"] for f in fns) or 1
    hv = halstead_volume(src)
    mi = max(0.0, min(100.0, (171 - 5.2 * math.log(max(hv, 1)) - 0.23 * cc_total - 16.2 * math.log(max(code, 1))) * 100 / 171)) if code else 100.0
    return {"path": rel, "lang": lang, "lines": len(lines), "chars": len(src), "code": code, "comments": comments, "blank": blank, "functions": sorted(fns, key=lambda f: f["start"]),
            "cc": cc_total if fns else 0, "max_cc": max((f["cc"] for f in fns), default=0), "mi": round(mi, 1), "smells": sorted(smells, key=lambda s: s["line"]),
            "parse_error": parse_error}


# ───────────────────────── Doublons ─────────────────────────
WINDOW = 6


def _norm(ln: str) -> str:
    s = ln.strip()
    if not s or s in "{}[]();" or s.startswith(("#", "//", "*", "/*", "import ", "from ", "}", "@")) and len(s) < 60 and not s.startswith("}"):
        return ""
    return re.sub(r"\s+", " ", s)


def find_duplicates(sources: dict[str, list[str]]) -> list[dict]:
    index = defaultdict(list)
    normed = {}
    for path, lines in sources.items():
        seq = [(i + 1, _norm(ln)) for i, ln in enumerate(lines)]
        seq = [(n, s) for n, s in seq if s and len(s) > 3]
        normed[path] = seq
        for k in range(len(seq) - WINDOW + 1):
            h = hashlib.md5("\n".join(s for _, s in seq[k:k + WINDOW]).encode()).hexdigest()
            index[h].append((path, k))
    pairs = defaultdict(set)
    for occ in index.values():
        if len(occ) < 2 or len(occ) > 20:
            continue
        a = occ[0]
        for b in occ[1:]:
            if a[0] == b[0] and abs(a[1] - b[1]) < WINDOW:
                continue
            pairs[(a[0], b[0], b[1] - a[1])].add(a[1])
    blocks = []
    for (pa, pb, off), starts in pairs.items():
        starts = sorted(starts)
        run = [starts[0]]
        for s in starts[1:] + [None]:
            if s is not None and s == run[-1] + 1:
                run.append(s)
                continue
            k0, k1 = run[0], run[-1] + WINDOW - 1
            sa, sb = normed[pa], normed[pb]
            blocks.append({"a": pa, "a_start": sa[k0][0], "a_end": sa[k1][0], "b": pb, "b_start": sb[k0 + off][0], "b_end": sb[k1 + off][0], "lines": k1 - k0 + 1})
            if s is not None:
                run = [s]
    blocks.sort(key=lambda b: -b["lines"])
    return blocks[:200]


# ───────────────────────── Git ─────────────────────────
FIX_RE = re.compile(r"\b(fix|bug|crash|hotfix|patch|corrig|répar|regression|erreur)", re.I)


def git_history(root: str, max_commits: int = 3000) -> dict | None:
    if not os.path.isdir(os.path.join(root, ".git")):
        return None
    try:
        out = subprocess.run(["git", "-C", root, "log", f"-n{max_commits}", "--no-merges", "--numstat", "--date=iso-strict", "--format=@@%H\t%an\t%ad\t%s"],
                             capture_output=True, text=True, timeout=60, errors="replace").stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    commits, cur = [], None
    for ln in out.splitlines():
        if ln.startswith("@@"):
            h, author, date, msg = (ln[2:].split("\t", 3) + ["", "", ""])[:4]
            cur = {"hash": h[:8], "author": author, "date": date, "msg": msg, "files": []}
            commits.append(cur)
        elif ln.strip() and cur is not None:
            parts = ln.split("\t")
            if len(parts) == 3:
                a, d, f = parts
                if "=>" in f:
                    f = re.sub(r"\{([^}]*) => ([^}]*)\}", r"\2", f).split(" => ")[-1].replace("//", "/")
                cur["files"].append((f, int(a) if a.isdigit() else 0, int(d) if d.isdigit() else 0))
    if not commits:
        return None
    churn, ncommits, fixes, authors_by_file = Counter(), Counter(), Counter(), defaultdict(Counter)
    authors, weeks, couple = Counter(), Counter(), Counter()
    for c in commits:
        is_fix = bool(FIX_RE.search(c["msg"]))
        c["fix"] = is_fix
        authors[c["author"]] += 1
        try:
            dt = datetime.fromisoformat(c["date"])
            weeks[dt.strftime("%G-S%V")] += 1
        except ValueError:
            pass
        files = [f for f, _, _ in c["files"]]
        for f, a, d in c["files"]:
            churn[f] += a + d
            ncommits[f] += 1
            authors_by_file[f][c["author"]] += a + d + 1
            if is_fix:
                fixes[f] += 1
        if 2 <= len(files) <= 12:
            for i in range(len(files)):
                for j in range(i + 1, len(files)):
                    couple[tuple(sorted((files[i], files[j])))] += 1
    per_file = {}
    for f in ncommits:
        total = sum(authors_by_file[f].values())
        top = authors_by_file[f].most_common()
        bus, acc = 0, 0
        for _, w in top:
            acc += w
            bus += 1
            if acc >= total * 0.5:
                break
        per_file[f] = {"churn": churn[f], "commits": ncommits[f], "fixes": fixes[f], "authors": len(top), "owner": top[0][0], "bus": bus,
                       "owner_share": round(top[0][1] / total, 2)}
    first, last = commits[-1]["date"], commits[0]["date"]
    return {"commits": len(commits), "authors": authors.most_common(), "first": first, "last": last, "weeks": sorted(weeks.items()),
            "files": per_file, "coupling": [{"a": a, "b": b, "n": n} for (a, b), n in couple.most_common(15) if n >= 2],
            "recent": [{k: c[k] for k in ("hash", "author", "date", "msg", "fix")} | {"n": len(c["files"])} for c in commits[:40]],
            "fix_ratio": round(sum(c["fix"] for c in commits) / len(commits), 3)}


# ───────────────────────── Projet complet ─────────────────────────
def walk(root: str):
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not x.startswith(".") and not x.endswith(".egg-info"))
        for f in sorted(files):
            if os.path.splitext(f)[1].lower() in LANGS and not f.endswith((".min.js", ".d.ts")):
                yield os.path.join(d, f)


def analyze_project(root: str, name: str | None = None, max_files: int = 3000) -> dict:
    root = os.path.abspath(root)
    files, sources = [], {}
    for p in walk(root):
        if len(files) >= max_files:
            break
        rel = os.path.relpath(p, root).replace(os.sep, "/")
        r = analyze_file(p, rel)
        if r:
            files.append(r)
            sources[rel] = open(p, encoding="utf-8", errors="replace").read().splitlines()
    dups = find_duplicates(sources)
    git = git_history(root)
    dead = dead_code(files, sources)
    dup_lines = defaultdict(set)
    for b in dups:
        dup_lines[b["a"]].update(range(b["a_start"], b["a_end"] + 1))
        dup_lines[b["b"]].update(range(b["b_start"], b["b_end"] + 1))
    for f in files:
        f["dup_lines"] = len(dup_lines.get(f["path"], ()))
        g = (git or {}).get("files", {}).get(f["path"])
        f["git"] = g
        f["score"] = sum(SEV[s["sev"]] for s in f["smells"])
    hotspots = compute_hotspots(files)
    summary = summarize(files, dups, git, dead, hotspots)
    return {"name": name or os.path.basename(root.rstrip("/")), "root": root, "files": files, "duplicates": dups, "git": git, "dead": dead,
            "hotspots": hotspots, "summary": summary, "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def dead_code(files: list[dict], sources: dict[str, list[str]]) -> list[dict]:
    """Fonctions jamais référencées ailleurs (approximation par recherche de nom)."""
    words = Counter()
    for lines in sources.values():
        words.update(re.findall(r"[A-Za-z_$][\w$]*", "\n".join(lines)))
    out = []
    for f in files:
        for fn in f["functions"]:
            n = fn["name"]
            if fn["decorated"] or n.startswith(("test", "__", "_on", "on")) or n in ("main", "setup", "constructor", "render", "init", "run", "handle", "default", "tearDown", "setUp") or "::" in n:
                continue
            if f["path"].split("/")[-1].startswith("test"):
                continue
            if words[n] <= 1:
                out.append({"path": f["path"], "name": n, "line": fn["start"], "length": fn["length"]})
    return out[:300]


def compute_hotspots(files: list[dict]) -> list[dict]:
    if not files:
        return []
    max_cc = max((f["cc"] for f in files), default=1) or 1
    max_churn = max(((f["git"] or {}).get("churn", 0) for f in files), default=0)
    out = []
    for f in files:
        churn = (f["git"] or {}).get("churn", 0)
        c = f["cc"] / max_cc
        h = (math.sqrt(c * (churn / max_churn)) if max_churn else c * 0.6) + 0.15 * min(1, f["score"] / 40)
        out.append({"path": f["path"], "cc": f["cc"], "churn": churn, "fixes": (f["git"] or {}).get("fixes", 0), "mi": f["mi"], "score": round(min(1.0, h), 3)})
    out.sort(key=lambda h: -h["score"])
    return out


GRADES = [(85, "A", "En pleine forme"), (70, "B", "Bonne santé"), (55, "C", "Quelques symptômes"), (40, "D", "État préoccupant"), (0, "E", "Pronostic vital engagé")]
KIND_LABEL = {"long-function": "fonctions-fleuves", "complexity": "complexité excessive", "secret": "secrets en dur", "eval": "exécution dynamique de code",
              "shell": "injections shell", "bare-except": "gestion d'erreurs approximative", "swallowed": "erreurs avalées", "xss": "risques XSS",
              "overflow": "débordements de tampon", "nesting": "imbrications profondes", "params": "signatures surchargées", "deserialize": "désérialisation dangereuse",
              "mutable-default": "arguments par défaut mutables", "tls": "TLS désactivé", "syntax": "erreurs de syntaxe"}


def summarize(files, dups, git, dead, hotspots) -> dict:
    code = sum(f["code"] for f in files) or 1
    kloc = code / 1000
    smells = [s | {"path": f["path"]} for f in files for s in f["smells"]]
    by_sev = Counter(s["sev"] for s in smells)
    by_kind = Counter(s["kind"] for s in smells)
    weighted = sum(SEV[s["sev"]] for s in smells if s["kind"] not in ("todo", "loose-eq", "var", "debug"))
    dup_ratio = sum(f["dup_lines"] for f in files) / code
    fns = [fn | {"path": f["path"]} for f in files for fn in f["functions"]]
    mi = sum(f["mi"] * f["code"] for f in files) / code
    complex_share = sum(fn["length"] for fn in fns if fn["cc"] > LIMITS["cc_warn"]) / code
    ekloc = max(kloc, sum(f.get("chars", 0) for f in files) / 45000) or 0.1  # taille « effective » : les lignes très denses comptent plus
    health = 100.0
    health -= min(25, weighted / max(ekloc, 0.3) * 0.2)
    health -= min(20, dup_ratio * 120)
    health -= min(20, complex_share * 50)
    health -= min(15, max(0, 40 - mi) * 0.5)
    health -= min(15, by_sev["crit"] * 1.5)
    health = max(0.0, round(health, 1))
    grade, verdict = next((g, v) for th, g, v in GRADES if health >= th)
    # rapport d'autopsie : cause du décès = catégorie la plus « lourde »
    weight = Counter()
    for s in smells:
        if s["kind"] in KIND_LABEL:
            weight[s["kind"]] += SEV[s["sev"]]
    if dup_ratio > 0.05:
        weight["duplication"] = int(dup_ratio * 400)
    causes = []
    for k, w in weight.most_common(3):
        if k == "duplication":
            causes.append(f"copier-coller chronique ({dup_ratio:.0%} du code dupliqué)")
        else:
            causes.append(f"{KIND_LABEL[k]} ({by_kind[k]} cas)")
    worst = sorted(fns, key=lambda f: -f["cc"])[:10]
    langs = Counter()
    for f in files:
        langs[f["lang"]] += f["code"]
    return {"files": len(files), "code": code, "comments": sum(f["comments"] for f in files), "functions": len(fns), "smells": len(smells),
            "by_sev": dict(by_sev), "by_kind": by_kind.most_common(), "dup_ratio": round(dup_ratio, 4), "dup_blocks": len(dups), "mi": round(mi, 1),
            "health": health, "grade": grade, "verdict": verdict, "causes": causes, "worst_functions": worst, "languages": langs.most_common(),
            "dead": len(dead), "avg_cc": round(sum(f["cc"] for f in fns) / max(1, len(fns)), 2),
            "hotspot": hotspots[0]["path"] if hotspots else None, "commits": (git or {}).get("commits", 0)}
