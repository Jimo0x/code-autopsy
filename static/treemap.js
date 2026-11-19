/* Treemap « squarified » (Bruls, Huizing, van Wijk) hiérarchique — sans dépendance */
const Treemap = (() => {
  function build(files, valueOf) {
    const root = { name: "", path: "", children: [], dir: true };
    for (const f of files) {
      const parts = f.path.split("/"); let node = root;
      parts.forEach((p, i) => {
        if (i === parts.length - 1) { node.children.push({ name: p, path: f.path, file: f, value: Math.max(1, valueOf(f)) }); return; }
        let c = node.children.find(c => c.dir && c.name === p);
        if (!c) { c = { name: p, path: (node.path ? node.path + "/" : "") + p, children: [], dir: true }; node.children.push(c); }
        node = c;
      });
    }
    const sum = n => n.dir ? (n.value = n.children.reduce((a, c) => a + sum(c), 0)) : n.value; sum(root);
    // fusion des dossiers à enfant unique (src/main/java/... → un seul niveau)
    const squash = n => { if (!n.dir) return n; n.children = n.children.map(squash);
      if (n !== root && n.children.length === 1 && n.children[0].dir) { const c = n.children[0]; return { ...c, name: n.name + "/" + c.name }; } return n; };
    return squash(root);
  }
  const worst = (row, w) => { const s = row.reduce((a, r) => a + r.area, 0), mx = Math.max(...row.map(r => r.area)), mn = Math.min(...row.map(r => r.area)); return Math.max(w * w * mx / (s * s), s * s / (w * w * mn)); };
  function squarify(items, x, y, w, h, out) {
    items = items.filter(i => i.area > 0).sort((a, b) => b.area - a.area);
    while (items.length) {
      const side = Math.min(w, h); let row = [items[0]], i = 1;
      while (i < items.length && worst([...row, items[i]], side) <= worst(row, side)) row.push(items[i++]);
      items = items.slice(i); const s = row.reduce((a, r) => a + r.area, 0);
      if (w >= h) { const cw = s / h; let cy = y; for (const r of row) { const rh = r.area / cw; out.push([r, x, cy, cw, rh]); cy += rh; } x += cw; w -= cw; }
      else { const ch = s / w; let cx = x; for (const r of row) { const rw = r.area / ch; out.push([r, cx, y, rw, ch]); cx += rw; } y += ch; h -= ch; }
    }
  }
  function layout(node, x, y, w, h, depth = 0, out = []) {
    if (!node.dir) { out.push({ node, x, y, w, h, depth }); return out; }
    if (depth > 0) out.push({ node, x, y, w, h, depth, dir: true });
    const head = depth > 0 && h > 40 && w > 60 ? 18 : 0, pad = depth > 0 ? 3 : 0;
    const ix = x + pad, iy = y + head + pad, iw = Math.max(0, w - pad * 2), ih = Math.max(0, h - head - pad * 2), tot = node.value || 1;
    const items = node.children.map(c => ({ c, area: c.value / tot * iw * ih })), placed = [];
    squarify(items, ix, iy, iw, ih, placed);
    for (const [it, cx, cy, cw, ch] of placed) layout(it.c, cx, cy, cw, ch, depth + 1, out);
    return out;
  }
  return { build, layout };
})();
