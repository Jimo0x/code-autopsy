let A = null, fileView = null, sortKey = "cc", sortDir = -1, sevF = "all", kindF = "", mapMetric = "cc", mapRects = [];
const SEVL = { crit: "Critique", warn: "Alerte", info: "Info" };
const KIND = { "long-function": "Fonction-fleuve", complexity: "Complexité", secret: "Secret en dur", eval: "eval / exec", shell: "Injection shell", "bare-except": "except nu",
  swallowed: "Erreur avalée", xss: "XSS", overflow: "Débordement", nesting: "Imbrication", params: "Trop de paramètres", deserialize: "Désérialisation", "mutable-default": "Défaut mutable",
  tls: "TLS désactivé", todo: "TODO/FIXME", "unused-import": "Import inutilisé", "loose-eq": "Égalité faible", var: "var", debug: "Debug oublié", "star-import": "import *",
  global: "global", "none-compare": "== None", "weak-hash": "Hash faible", syntax: "Syntaxe" };
const heat = t => { t = Math.max(0, Math.min(1, t)); const a = [[46, 204, 113], [245, 165, 36], [229, 23, 47]], i = t < .5 ? 0 : 1, k = t < .5 ? t * 2 : (t - .5) * 2;
  return `rgb(${a[i].map((c, j) => Math.round(c + (a[i + 1][j] - c) * k)).join(",")})`; };
const ccColor = cc => heat((cc - 3) / 22);
const show = (el, on) => el.hidden = !on;

/* ───────── accueil ───────── */
async function history() {
  const h = await api("/api/analyses");
  $("#history").innerHTML = h.length ? h.map(a => `<div class="item hist clickable" data-id="${a.id}"><span class="gb g-${a.grade}">${a.grade}</span><b>${esc(a.name)}</b><div class="dim mono" style="font-size:12px">${new Date(a.at).toLocaleString("fr-FR")} · santé ${a.health}</div></div>`).join("")
    : `<div class="empty" style="grid-column:1/-1">Aucune autopsie pour l'instant.</div>`;
  $$(".hist").forEach(e => e.onclick = () => open(e.dataset.id));
}
async function run(body) {
  show($("#loading"), true);
  try { const r = await api("/api/analyze", { method: "POST", body }); await open(r.id); } catch (e) { toast("⚠ " + e.message); } finally { show($("#loading"), false); }
}
$("#demoBtn").onclick = () => run({ demo: true });
$("#pathBtn").onclick = () => $("#path").value.trim() && run({ path: $("#path").value.trim() });
$("#path").onkeydown = e => e.key === "Enter" && $("#pathBtn").click();
const drop = $("#drop"), zip = f => { const fd = new FormData(); fd.append("archive", f); run(fd); };
drop.onclick = () => $("#zip").click(); $("#zip").onchange = e => e.target.files[0] && zip(e.target.files[0]);
drop.ondragover = e => { e.preventDefault(); drop.classList.add("over"); }; drop.ondragleave = () => drop.classList.remove("over");
drop.ondrop = e => { e.preventDefault(); drop.classList.remove("over"); e.dataTransfer.files[0] && zip(e.dataTransfer.files[0]); };
$("#newBtn").onclick = () => { location.hash = ""; home(); };
function home() { A = null; show($("#home"), true); show($("#res"), false); show($("#newBtn"), false); show($("#mdBtn"), false); $("#projName").textContent = ""; history(); }

/* ───────── ouverture d'une analyse ───────── */
async function open(id) {
  A = await api("/api/analysis/" + id); location.hash = id;
  A.fns = A.files.flatMap(f => f.functions.map(fn => ({ ...fn, path: f.path })));
  const dead = new Set(A.dead.map(d => d.path + ":" + d.line)); A.fns.forEach(fn => fn.dead = dead.has(fn.path + ":" + fn.start));
  A.smells = A.files.flatMap(f => f.smells.map(s => ({ ...s, path: f.path })));
  show($("#home"), false); show($("#res"), true); show($("#newBtn"), true); show($("#mdBtn"), true);
  $("#mdBtn").href = `/api/analysis/${id}/report.md`; $("#projName").textContent = A.name; show($("#fileTab"), false);
  tab("report");
}
function tab(t) {
  $$("#tabs .tab").forEach(e => e.classList.toggle("on", e.dataset.t === t)); $$("#res section").forEach(s => show(s, s.dataset.p === t));
  ({ report, map: drawMap, hot, fns: fnTable, smells, dups, git, file: () => {} })[t]();
}
$$("#tabs .tab").forEach(e => e.onclick = () => tab(e.dataset.t));

/* ───────── rapport ───────── */
function report() {
  const s = A.summary;
  $("#grade").textContent = s.grade; $("#grade").className = "grade g-" + s.grade; $("#verdict").textContent = s.verdict;
  $("#healthBar").style.width = s.health + "%"; $("#healthBar").style.background = heat(1 - s.health / 100);
  $("#healthTxt").textContent = `Santé ${s.health}/100 · analysé le ${new Date(A.analyzed_at).toLocaleString("fr-FR")}`;
  $("#causes").innerHTML = (s.causes.length ? s.causes : ["Aucune pathologie majeure — le patient est en vie."]).map(c => `<li>${esc(c)}</li>`).join("");
  const crit = s.by_sev.crit || 0;
  $("#vitals").innerHTML = [["Lignes de code", s.code.toLocaleString("fr-FR"), `${s.files} fichiers · ${s.comments} lignes de commentaires`], ["Fonctions", s.functions, `complexité moyenne ${s.avg_cc}`],
    ["Maintenabilité", s.mi, s.mi >= 40 ? "bonne" : s.mi >= 20 ? "moyenne" : "faible"], ["Symptômes", s.smells, `<span class="${crit ? "red" : ""}">${crit} critiques</span>`],
    ["Code dupliqué", (s.dup_ratio * 100).toFixed(1) + " %", `${s.dup_blocks} blocs`], ["Code mort ?", s.dead, "fonctions jamais référencées"]]
    .map(([l, v, sub]) => `<div class="stat"><div class="l">${l}</div><div class="v">${v}</div><div class="s">${sub}</div></div>`).join("");
  Charts.donut($("#cvLang"), s.languages.map(l => l[0]), s.languages.map(l => l[1]), { center: s.code });
  const k = s.by_kind.slice(0, 7), km = Math.max(1, ...k.map(x => x[1]));
  $("#kinds").innerHTML = k.map(([kind, n]) => `<div class="hrow" style="grid-template-columns:1fr 110px 26px;cursor:default"><span>${KIND[kind] || kind}</span><div class="meter"><i style="width:${n / km * 100}%"></i></div><b class="mono" style="text-align:right">${n}</b></div>`).join("");
  $("#hotMini").innerHTML = hotRows(A.hotspots.slice(0, 6));
  $("#worst").innerHTML = s.worst_functions.map(f => fnCard(f)).join("");
  bindOpeners();
}
const fnCard = f => `<div class="fn" data-open="${esc(f.path)}" data-line="${f.start}"><span class="ccpill" style="background:${ccColor(f.cc)}22;color:${ccColor(f.cc)}">CC ${f.cc}</span><b>${esc(f.name)}</b><div class="p">${esc(f.path)}:${f.start} · ${f.length} lignes · ${f.params} param.</div></div>`;
const hotRows = hs => hs.map((h, i) => `<div class="hrow" data-open="${esc(h.path)}"><span class="dim mono">${i + 1}</span><div><div class="mono">${esc(h.path)}</div><div class="dim" style="font-size:11.5px">CC ${h.cc} · ${h.churn} lignes modifiées · ${h.fixes} correctifs</div></div><div class="meter"><i style="width:${h.score * 100}%;background:${heat(h.score)}"></i></div></div>`).join("");
function bindOpeners() { $$("[data-open]").forEach(e => e.onclick = () => openFile(e.dataset.open, +e.dataset.line || 0)); }

/* ───────── carte ───────── */
$$("#mapMetric button").forEach(b => b.onclick = () => { mapMetric = b.dataset.m; $$("#mapMetric button").forEach(z => z.classList.toggle("on", z === b)); drawMap(); });
function metricOf(f) {
  const maxChurn = Math.max(1, ...A.files.map(x => (x.git || {}).churn || 0));
  return { cc: (f.max_cc - 3) / 20, mi: 1 - f.mi / 60, churn: ((f.git || {}).churn || 0) / maxChurn, score: f.score / 30, dup: f.dup_lines / Math.max(1, f.code) * 3 }[mapMetric];
}
function drawMap() {
  const cv = $("#cvMap"), dpr = devicePixelRatio || 1, W = cv.clientWidth, H = cv.clientHeight; cv.width = W * dpr; cv.height = H * dpr;
  const x = cv.getContext("2d"); x.setTransform(dpr, 0, 0, dpr, 0, 0); x.clearRect(0, 0, W, H);
  const tree = Treemap.build(A.files, f => f.code || 1); mapRects = Treemap.layout(tree, 0, 0, W, H);
  for (const r of mapRects) {
    if (r.dir) { x.fillStyle = "#0f0f12"; x.strokeStyle = "#34343e"; x.fillRect(r.x, r.y, r.w, r.h); x.strokeRect(r.x + .5, r.y + .5, r.w - 1, r.h - 1);
      if (r.h > 40 && r.w > 60) { x.fillStyle = "#8d8d99"; x.font = "600 11px JetBrains Mono, monospace"; x.fillText(clip(x, r.node.name + "/", r.w - 8), r.x + 5, r.y + 13); } continue; }
    const f = r.node.file, t = metricOf(f); x.fillStyle = heat(t); x.globalAlpha = .22 + .6 * Math.min(1, Math.max(0, t) * .7 + .3); x.fillRect(r.x + 1, r.y + 1, r.w - 2, r.h - 2); x.globalAlpha = 1;
    x.strokeStyle = "#09090b"; x.lineWidth = 1.5; x.strokeRect(r.x + .5, r.y + .5, r.w - 1, r.h - 1);
    if (r.w > 50 && r.h > 22) { x.fillStyle = "#fff"; x.font = "600 12px Inter, sans-serif"; x.fillText(clip(x, r.node.name, r.w - 10), r.x + 6, r.y + 16);
      if (r.h > 38) { x.fillStyle = "rgba(255,255,255,.7)"; x.font = "11px JetBrains Mono, monospace"; x.fillText(clip(x, `${f.code} l · CC ${f.max_cc} · MI ${f.mi}`, r.w - 10), r.x + 6, r.y + 31); } }
  }
}
function clip(x, s, w) { if (x.measureText(s).width <= w) return s; while (s.length > 1 && x.measureText(s + "…").width > w) s = s.slice(0, -1); return s + "…"; }
const hitMap = e => { const b = $("#cvMap").getBoundingClientRect(), mx = e.clientX - b.left, my = e.clientY - b.top; return mapRects.filter(r => !r.dir && mx >= r.x && mx <= r.x + r.w && my >= r.y && my <= r.y + r.h).pop(); };
$("#cvMap").onmousemove = e => { const r = hitMap(e), tip = $("#tip"); if (!r) { tip.hidden = true; return; } const f = r.node.file, g = f.git;
  tip.hidden = false; tip.style.left = Math.min(innerWidth - 350, e.clientX + 14) + "px"; tip.style.top = e.clientY + 14 + "px";
  tip.innerHTML = `<b class="mono">${esc(f.path)}</b><div class="muted" style="margin-top:4px">${f.lang} · ${f.code} lignes · ${f.functions.length} fonctions<br>Complexité max ${f.max_cc} · maintenabilité ${f.mi}<br>${f.smells.length} symptômes · ${f.dup_lines} lignes dupliquées${g ? `<br>${g.commits} commits · ${g.churn} lignes modifiées · ${g.fixes} correctifs<br>propriétaire : ${esc(g.owner)} (${Math.round(g.owner_share * 100)} %)` : ""}</div>`; };
$("#cvMap").onmouseleave = () => $("#tip").hidden = true;
$("#cvMap").onclick = e => { const r = hitMap(e); if (r) { $("#tip").hidden = true; openFile(r.node.file.path); } };

/* ───────── points chauds ───────── */
let hotPts = [];
function hot() {
  $("#hotList").innerHTML = hotRows(A.hotspots.slice(0, 25)); bindOpeners();
  const cv = $("#cvHot"), dpr = devicePixelRatio || 1, W = cv.clientWidth, H = cv.clientHeight; cv.width = W * dpr; cv.height = H * dpr;
  const x = cv.getContext("2d"); x.setTransform(dpr, 0, 0, dpr, 0, 0); const P = { l: 46, r: 110, t: 24, b: 36 };
  const hasGit = !!A.git, xs = A.files.map(f => hasGit ? (f.git || {}).churn || 0 : f.code), maxX = Math.max(1, ...xs) * 1.08, maxY = Math.max(1, ...A.files.map(f => f.cc)) * 1.08;
  const sx = v => P.l + (W - P.l - P.r) * Math.sqrt(v / maxX), sy = v => H - P.b - (H - P.t - P.b) * Math.sqrt(v / maxY);
  const g = x.createLinearGradient(P.l, H - P.b, W - P.r, P.t); g.addColorStop(0, "rgba(229,23,47,0)"); g.addColorStop(1, "rgba(229,23,47,.16)");
  x.fillStyle = g; x.fillRect((P.l + W - P.r) / 2, P.t, (W - P.r - P.l) / 2, (H - P.b - P.t) / 2);
  x.strokeStyle = "#26262e"; x.strokeRect(P.l, P.t, W - P.l - P.r, H - P.t - P.b); x.beginPath(); x.moveTo((P.l + W - P.r) / 2, P.t); x.lineTo((P.l + W - P.r) / 2, H - P.b); x.moveTo(P.l, (P.t + H - P.b) / 2); x.lineTo(W - P.r, (P.t + H - P.b) / 2); x.setLineDash([4, 4]); x.stroke(); x.setLineDash([]);
  x.fillStyle = "#8d8d99"; x.font = "11px Inter"; x.textAlign = "center"; x.fillText(hasGit ? "lignes modifiées (churn, échelle √) →" : "lignes de code (pas d'historique Git) →", (P.l + W - P.r) / 2, H - 10);
  x.save(); x.translate(14, (P.t + H - P.b) / 2); x.rotate(-Math.PI / 2); x.fillText("complexité totale →", 0, 0); x.restore(); x.textAlign = "left";
  x.fillStyle = "rgba(255,138,152,.8)"; x.fillText("ZONE DANGEREUSE", (P.l + W - P.r) / 2 + 8, P.t + 16);
  hotPts = A.files.map((f, i) => ({ f, px: sx(xs[i]), py: sy(f.cc), r: 3 + Math.sqrt(f.code) * .5 })).sort((a, b) => b.r - a.r);
  for (const p of hotPts) { const fx = (p.f.git || {}).fixes || 0; x.beginPath(); x.arc(p.px, p.py, p.r, 0, 7); x.fillStyle = fx ? `rgba(229,23,47,${Math.min(.85, .3 + fx * .1)})` : "rgba(236,236,241,.25)"; x.fill(); x.strokeStyle = fx ? "#ff3b52" : "#5d5d69"; x.stroke(); }
  x.fillStyle = "#ececf1"; x.font = "11px JetBrains Mono, monospace";
  A.hotspots.slice(0, 5).forEach(h => { const p = hotPts.find(q => q.f.path === h.path); if (p) x.fillText(h.path.split("/").pop(), p.px + p.r + 4, p.py + 4); });
}
$("#cvHot").onclick = e => { const b = e.target.getBoundingClientRect(), mx = e.clientX - b.left, my = e.clientY - b.top; const p = hotPts.filter(p => Math.hypot(p.px - mx, p.py - my) < p.r + 3).pop(); if (p) openFile(p.f.path); };

/* ───────── fonctions ───────── */
$$("#fnTable th").forEach(th => th.onclick = () => { const k = th.dataset.k; sortDir = sortKey === k ? -sortDir : (k === "name" || k === "path" ? 1 : -1); sortKey = k; fnTable(); });
$("#fnSearch").oninput = fnTable; $("#deadOnly").onchange = fnTable;
function fnTable() {
  const q = $("#fnSearch").value.toLowerCase(), dead = $("#deadOnly").checked;
  const rows = A.fns.filter(f => (!q || (f.name + f.path).toLowerCase().includes(q)) && (!dead || f.dead))
    .sort((a, b) => (a[sortKey] > b[sortKey] ? 1 : a[sortKey] < b[sortKey] ? -1 : 0) * sortDir).slice(0, 500);
  $$("#fnTable th").forEach(th => th.classList.toggle("sorted", th.dataset.k === sortKey));
  $("#fnTable tbody").innerHTML = rows.map(f => `<tr data-open="${esc(f.path)}" data-line="${f.start}" style="cursor:pointer"><td><b class="mono">${esc(f.name)}</b>${f.dead ? ' <span class="badge warn">mort ?</span>' : ""}</td><td class="mono dim">${esc(f.path)}:${f.start}</td>
    <td><span class="ccpill" style="float:none;background:${ccColor(f.cc)}22;color:${ccColor(f.cc)}">${f.cc}</span></td><td class="mono">${f.length}</td><td class="mono">${f.params}</td><td class="mono">${f.nest}</td></tr>`).join("")
    || `<tr><td colspan="6" class="dim" style="text-align:center;padding:30px">Aucune fonction</td></tr>`;
  bindOpeners();
}

/* ───────── symptômes ───────── */
$$("#sevFilter button").forEach(b => b.onclick = () => { sevF = b.dataset.s; $$("#sevFilter button").forEach(z => z.classList.toggle("on", z === b)); smells(); });
$("#kindFilter").onchange = e => { kindF = e.target.value; smells(); };
function smells() {
  const kinds = [...new Set(A.smells.map(s => s.kind))];
  $("#kindFilter").innerHTML = `<option value="">Tous les types (${A.smells.length})</option>` + kinds.map(k => `<option value="${k}" ${k === kindF ? "selected" : ""}>${KIND[k] || k} (${A.smells.filter(s => s.kind === k).length})</option>`).join("");
  const order = { crit: 0, warn: 1, info: 2 };
  const list = A.smells.filter(s => (sevF === "all" || s.sev === sevF) && (!kindF || s.kind === kindF)).sort((a, b) => order[a.sev] - order[b.sev] || a.path.localeCompare(b.path) || a.line - b.line);
  $("#smellList").innerHTML = list.slice(0, 600).map(s => `<div class="sm ${s.sev}" data-open="${esc(s.path)}" data-line="${s.line}"><span class="badge ${s.sev === "crit" ? "red" : s.sev === "warn" ? "warn" : ""}">${SEVL[s.sev]}</span>
    <div>${esc(s.msg)}<div class="loc">${esc(s.path)}:${s.line}</div></div><span class="dim" style="font-size:12px">${KIND[s.kind] || s.kind}</span></div>`).join("") || `<div class="empty">Aucun symptôme 🎉</div>`;
  bindOpeners();
}

/* ───────── doublons ───────── */
async function dups() {
  if (!A.duplicates.length) { $("#dupList").innerHTML = `<div class="empty">Aucun bloc dupliqué (fenêtre de 6 lignes significatives).</div>`; return; }
  $("#dupList").innerHTML = `<p class="muted">${A.duplicates.length} blocs dupliqués — corriger un bug dans l'un sans l'autre est une cause classique de régression.</p>` + A.duplicates.slice(0, 20).map((d, i) => `<div class="card dup" id="dup${i}">
    <div><div class="h" data-open="${esc(d.a)}" data-line="${d.a_start}">${esc(d.a)}:${d.a_start}-${d.a_end}</div><pre>…</pre></div>
    <div><div class="h" data-open="${esc(d.b)}" data-line="${d.b_start}">${esc(d.b)}:${d.b_start}-${d.b_end}</div><pre>…</pre></div></div>`).join("");
  bindOpeners();
  const cache = {}; const src = async p => cache[p] ||= (await api(`/api/analysis/${A.id}/file?path=${encodeURIComponent(p)}`)).lines;
  for (const [i, d] of A.duplicates.slice(0, 20).entries()) { try { const [la, lb] = await Promise.all([src(d.a), src(d.b)]); const pre = $$(`#dup${i} pre`);
    pre[0].innerHTML = highlight(la.slice(d.a_start - 1, d.a_end).join("\n")); pre[1].innerHTML = highlight(lb.slice(d.b_start - 1, d.b_end).join("\n")); } catch { } }
}

/* ───────── historique git ───────── */
function git() {
  const g = A.git; show($("#gitNone"), !g); show($("#gitBox"), !!g); if (!g) return;
  const d = s => new Date(s).toLocaleDateString("fr-FR", { day: "numeric", month: "short", year: "numeric" });
  $("#gitStats").innerHTML = [["Commits", g.commits], ["Auteurs", g.authors.length], ["Commits correctifs", Math.round(g.fix_ratio * 100) + " %"], ["Période", `${d(g.first)} → ${d(g.last)}`]]
    .map(([l, v]) => `<div class="stat"><div class="l">${l}</div><div class="v" style="font-size:${String(v).length > 12 ? 15 : 22}px">${v}</div></div>`).join("");
  Charts.bar($("#cvWeeks"), g.weeks.map(w => w[0].slice(5)), g.weeks.map(w => w[1]));
  Charts.donut($("#cvAuthors"), g.authors.slice(0, 7).map(a => a[0]), g.authors.slice(0, 7).map(a => a[1]));
  $("#coupling").innerHTML = g.coupling.length ? g.coupling.map(c => `<div class="hrow" style="grid-template-columns:1fr 50px"><div class="mono" style="font-size:12px">${esc(c.a)}<br><span class="dim">⇄</span> ${esc(c.b)}</div><b class="mono">${c.n}×</b></div>`).join("") : `<div class="dim">Aucun couplage récurrent.</div>`;
  const bus = Object.entries(g.files).filter(([p, f]) => f.commits >= 3 && f.owner_share >= .7).sort((a, b) => b[1].churn - a[1].churn).slice(0, 10);
  $("#bus").innerHTML = bus.length ? bus.map(([p, f]) => `<div class="hrow" style="grid-template-columns:1fr auto" data-open="${esc(p)}"><div class="mono" style="font-size:12px">${esc(p)}</div><span class="badge warn">${esc(f.owner)} · ${Math.round(f.owner_share * 100)} %</span></div>`).join("") : `<div class="dim">Connaissance bien répartie 👍</div>`;
  $("#commits").innerHTML = g.recent.map(c => `<div class="hrow" style="grid-template-columns:80px 1fr 150px 110px;cursor:default"><span class="mono dim">${c.hash}</span><span>${c.fix ? '<span class="badge red">correctif</span> ' : ""}${esc(c.msg)}</span><span class="muted">${esc(c.author)}</span><span class="dim mono" style="font-size:12px">${d(c.date)}</span></div>`).join("");
  bindOpeners();
}

/* ───────── fichier ───────── */
const KW = /\b(def|class|return|if|elif|else|for|while|try|except|finally|with|as|import|from|function|const|let|var|async|await|new|switch|case|break|continue|throw|catch|struct|static|void|int|char|public|private|lambda|yield|pass|raise|in|not|and|or|is|None|True|False|null|true|false|this|self|typeof|export|default)\b/g;
function highlight(src) {
  return esc(src).replace(/(&quot;|&#39;|`)(?:(?!\1).)*?\1|(#[^\n]*|\/\/[^\n]*)|\b(\d+\.?\d*)\b|\b([a-z_]+)\b/gi, (m, q, com, num, word) =>
    q ? `<span class="str">${m}</span>` : com ? `<span class="com">${m}</span>` : num ? `<span class="num">${m}</span>` : KW.test(word) ? (KW.lastIndex = 0, `<span class="kw">${m}</span>`) : (KW.lastIndex = 0, m));
}
async function openFile(path, line = 0) {
  let r; try { r = await api(`/api/analysis/${A.id}/file?path=${encodeURIComponent(path)}`); } catch (e) { return toast("⚠ " + e.message); }
  fileView = r; show($("#fileTab"), true); tab("file"); const f = r.file;
  $("#fLang").textContent = f.lang; $("#fPath").textContent = f.path;
  $("#fStats").innerHTML = [["Lignes", f.code], ["CC max", f.max_cc], ["Maintenabilité", f.mi], ["Symptômes", f.smells.length]].map(([l, v]) => `<div class="stat"><div class="l">${l}</div><div class="v" style="font-size:18px">${v}</div></div>`).join("");
  const lineCC = {}; f.functions.forEach(fn => { for (let i = fn.start; i <= fn.end; i++) lineCC[i] = Math.max(lineCC[i] || 0, fn.cc); });
  const notes = {}; f.smells.forEach(s => (notes[s.line] ||= []).push(s));
  const dupl = new Set(); r.duplicates.forEach(d => { const [s, e] = d.a === f.path ? [d.a_start, d.a_end] : [d.b_start, d.b_end]; for (let i = s; i <= e; i++) dupl.add(i); });
  $("#code").innerHTML = r.lines.map((ln, i) => { const n = i + 1, cc = lineCC[n];
    return `<div class="ln${dupl.has(n) ? " dupl" : ""}${notes[n] ? " hit" : ""}" id="L${n}"><span class="heat" style="background:${cc ? ccColor(cc) : "transparent"};opacity:${cc ? .8 : 0}"></span><span class="n">${n}</span><span>${highlight(ln)}${(notes[n] || []).map(s => `<span class="note ${s.sev}">${esc(s.msg)}</span>`).join("")}</span></div>`; }).join("");
  const g = f.git;
  $("#fSide").innerHTML = `<div class="kicker">Fonctions</div>${f.functions.map(fn => `<div class="f" data-line="${fn.start}"><span>${esc(fn.name)}</span><span style="color:${ccColor(fn.cc)}">CC ${fn.cc}</span></div>`).join("") || '<div class="dim">—</div>'}
    ${g ? `<hr><div class="kicker">Historique</div><div class="muted" style="font-size:13px;line-height:1.8;margin-top:6px">${g.commits} commits · ${g.churn} lignes modifiées<br>${g.fixes} commits correctifs<br>${g.authors} auteur(s) · facteur bus ${g.bus}<br>propriétaire : <b>${esc(g.owner)}</b> (${Math.round(g.owner_share * 100)} %)</div>` : ""}
    <hr><div class="kicker">Légende</div><div class="dim" style="font-size:12px;line-height:1.8;margin-top:6px">▌ barre de gauche = complexité de la fonction<br><span style="color:var(--info)">■</span> fond bleuté = code dupliqué<br><span class="red">■</span> fond rouge = symptôme</div>`;
  $$("#fSide .f").forEach(e => e.onclick = () => jump(+e.dataset.line)); if (line) jump(line); else $("#code").scrollTop = 0;
}
function jump(n) { $$(".ln.focus").forEach(e => e.classList.remove("focus")); const el = $("#L" + n); if (!el) return; el.classList.add("focus"); el.scrollIntoView({ block: "center" }); }
addEventListener("resize", () => { if (!A) return; const t = $("#tabs .tab.on").dataset.t; if (t === "map") drawMap(); if (t === "hot") hot(); });

location.hash.length > 2 ? open(location.hash.slice(1)).catch(home) : home();
