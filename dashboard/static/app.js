"use strict";
/* QuantumGuard dashboard. Captured file names are attacker-controlled, so every
   value placed into HTML goes through esc(). */

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const pct = (v, d = 0) => (v == null ? "n/a" : `${(v * 100).toFixed(d)}%`);
const short = (h, n = 12) => (h ? `${String(h).slice(0, n)}…` : "n/a");
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

async function api(path, body) {
  const options = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  };
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

const VIEWS = [
  { group: "LIVE DATA" },
  { id: "overview", label: "Command Center", crumb: "All phases", mode: "live", render: viewOverview, poll: 6000 },
  { id: "capture", label: "Capture", crumb: "Phase 1 and 2", mode: "live", render: viewCapture, poll: 6000 },
  { id: "graph", label: "Provenance Graph", crumb: "Phase 3", mode: "live", render: viewGraph },
  { id: "detection", label: "Detection", crumb: "Phase 4", mode: "live", render: viewDetection },
  { id: "seal", label: "Evidence Seal", crumb: "Phase 5", mode: "live", render: viewSeal },
  { id: "anchoring", label: "Anchoring", crumb: "Phase 6", mode: "live", render: viewAnchoring },
  { group: "SIMULATE" },
  { id: "lab", label: "Attack Lab", crumb: "Attack a copy", mode: "sandbox", render: viewLab },
  { id: "pipeline", label: "Pipeline Simulator", crumb: "All phases, simulated", mode: "sandbox", render: viewPipeline },
  { id: "survivability", label: "Survivability", crumb: "Phase 7", mode: "sandbox", render: viewSurvivability },
  { id: "scorecard", label: "Tamper Scorecard", crumb: "Every attack, every layer", mode: "sandbox", render: viewScorecard },
];
const MODES = { live: ["LIVE · READ ONLY", "live"], sandbox: ["SANDBOX · NOTHING SAVED", "sandbox"] };

let current = null, timer = null, token = 0;

function route() {
  const [id, action] = (location.hash.slice(1) || "overview").split("-");
  const view = VIEWS.find((v) => v.id === id) || VIEWS[1];
  clearInterval(timer);
  current = view;
  const mine = ++token;
  $("#title").textContent = view.label;
  $("#crumb").textContent = view.crumb;
  const [text, cls] = MODES[view.mode];
  const mode = $("#mode");
  mode.textContent = text;
  mode.className = `badge ${cls}`;
  $$("#nav a").forEach((a) => {
    if (a.dataset.id === view.id) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  const box = $("#view");
  box.innerHTML = '<div class="loading">Loading</div>';
  const alive = () => mine === token;
  Promise.resolve(view.render(box, alive, action)).catch((e) => showError(box, e));
  if (view.poll) {
    timer = setInterval(() => {
      if (!document.hidden && alive()) view.render(box, alive, null, true);
    }, view.poll);
  }
}

function showError(box, error) {
  box.innerHTML = `<div class="error"><b>Could not load this view.</b> ${esc(error.message)}</div>`;
}

const empty = (text, command) => `<div class="empty">${esc(text)}${command ? ` Run: <code>${esc(command)}</code>` : ""}</div>`;
const state = (kind, text) => `<span class="state s-${kind}">${esc(text)}</span>`;
const verdictKind = (v) => ({ CLEAN: "ok", SUSPICIOUS: "warn", TAMPERED: "fail" }[v] || "idle");

/* ------------------------------------------------------------- charts */

function lineChart(points, key, options = {}) {
  const w = 320, h = 132, l = 30, r = 10, t = 10, b = 22;
  const x = (i) => l + (i * (w - l - r)) / Math.max(1, points.length - 1);
  const y = (v) => t + (1 - v / 100) * (h - t - b);
  const path = points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(p[key]).toFixed(1)}`).join(" ");
  const area = `${path} L${x(points.length - 1)} ${y(0)} L${x(0)} ${y(0)} Z`;
  const grid = [0, 50, 100].map((v) =>
    `<line class="grid-line" x1="${l}" x2="${w - r}" y1="${y(v)}" y2="${y(v)}"/><text x="${l - 6}" y="${y(v) + 3.5}" text-anchor="end">${v}</text>`).join("");
  const ticks = points.map((p, i) => (i % 2 === 0
    ? `<text x="${x(i)}" y="${h - 7}" text-anchor="middle">${Math.round(p.damage * 100)}%</text>` : "")).join("");
  const band = (w - l - r) / Math.max(1, points.length - 1);
  const hits = points.map((p, i) =>
    `<rect class="hit" x="${x(i) - band / 2}" y="${t}" width="${band}" height="${h - t - b}" data-tip="${esc(`${key} at ${Math.round(p.damage * 100)}% damage: ${p[key].toFixed(1)}%`)}"/>`).join("");
  const last = points.length - 1;
  return `<svg class="chart" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(options.label || key)} as damage rises">
    ${grid}${ticks}<path class="area" d="${area}"/><path class="series" d="${path}"/>
    <circle class="pt" cx="${x(last)}" cy="${y(points[last][key])}" r="4"/>${hits}</svg>`;
}

function riskChart(scores, tier1, tier2) {
  if (!scores.length) return empty("No partitions scored.");
  const w = Math.max(420, scores.length * 34 + 60), h = 170, l = 34, r = 62, t = 10, b = 24;
  const max = Math.max(0.6, ...scores.map((s) => s.risk_score ?? s.score));
  const y = (v) => t + (1 - v / max) * (h - t - b);
  const step = (w - l - r) / scores.length;
  const width = Math.min(step - 2, 34);
  const tierClass = (tier) => (tier || "").startsWith("tier1") ? "t1" : (tier || "").startsWith("tier2") ? "t2" : "t3";
  const bars = scores.map((s, i) => {
    const value = s.risk_score ?? s.score, index = s.partition_index ?? s.index, tier = s.risk_tier ?? s.tier;
    const top = y(value), base = y(0), height = Math.max(1.5, base - top);
    const px = l + i * step + (step - width) / 2;
    const tip = `Partition ${index}\nscore ${value.toFixed(3)}\n${tier}${s.escalated_by ? `\nescalated by ${s.escalated_by}` : ""}`;
    return `<rect class="barmark ${tierClass(tier)}" x="${px}" y="${base - height}" width="${width}" height="${height}" rx="3"/>
      <rect class="hit" x="${l + i * step}" y="${t}" width="${step}" height="${h - t - b}" data-tip="${esc(tip)}"/>
      ${scores.length <= 24 ? `<text x="${px + width / 2}" y="${h - 8}" text-anchor="middle">${index}</text>` : ""}`;
  }).join("");
  const limit = (v, label) => `<line class="limit" x1="${l}" x2="${w - r}" y1="${y(v)}" y2="${y(v)}"/><text x="${w - r + 5}" y="${y(v) + 3.5}">${label}</text>`;
  return `<div class="tablewrap"><svg class="chart" style="min-width:${Math.min(w, 420)}px;max-width:${Math.max(560, w)}px" viewBox="0 0 ${w} ${h}" role="img" aria-label="Risk score per partition">
    <line class="grid-line" x1="${l}" x2="${w - r}" y1="${y(0)}" y2="${y(0)}"/><text x="${l - 6}" y="${y(0) + 3.5}" text-anchor="end">0</text>
    ${limit(tier2, "tier 2")}${limit(tier1, "tier 1")}${bars}</svg></div>
    <div class="legend"><span><i style="background:var(--bad);border-color:var(--bad)"></i>tier 1 immediate</span><span><i style="background:var(--warn);border-color:var(--warn)"></i>tier 2 batched</span><span><i style="background:#4f6a7d;border-color:#4f6a7d"></i>tier 3 local</span></div>`;
}

function timeline(rows) {
  if (rows.length < 2) return "";
  const w = 640, h = 92, l = 30, b = 18, t = 6;
  const max = Math.max(...rows.map((r) => r[1]));
  const step = (w - l) / rows.length, width = Math.max(2, Math.min(step - 2, 20));
  const fmt = (s) => new Date(s * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const bars = rows.map(([stamp, n], i) => {
    const height = Math.max(1.5, (n / max) * (h - b - t));
    return `<rect class="barmark" x="${l + i * step}" y="${h - b - height}" width="${width}" height="${height}" rx="2"/>
      <rect class="hit" x="${l + i * step}" y="${t}" width="${step}" height="${h - b - t}" data-tip="${esc(`${fmt(stamp)}: ${n} events`)}"/>`;
  }).join("");
  return `<svg class="chart" viewBox="0 0 ${w} ${h}" role="img" aria-label="Events per minute">
    <text x="${l - 5}" y="${t + 8}" text-anchor="end">${max}</text><line class="grid-line" x1="${l}" x2="${w}" y1="${h - b}" y2="${h - b}"/>
    <text x="${l}" y="${h - 5}">${fmt(rows[0][0])}</text><text x="${w}" y="${h - 5}" text-anchor="end">${fmt(rows[rows.length - 1][0])}</text>${bars}</svg>`;
}

const bars = (rows) => {
  const max = Math.max(1, ...rows.map((r) => r[1]));
  return rows.map(([name, n]) => `<div class="bar-row"><span>${esc(name)}</span>
    <span class="bar-track"><span class="bar-fill" style="width:${(n / max) * 100}%"></span></span><span class="num mono">${n}</span></div>`).join("");
};

/* ------------------------------------------------------------- graph */

function graphSvg(data) {
  if (!data || !data.nodes.length) return empty("This graph has no events to draw.");
  const W = 176, H = 56, gapX = 318, gapY = 88, pad = 42;
  const at = {};
  data.nodes.forEach((n) => { at[n.name] = { x: pad + n.column * gapX, y: pad + n.row * gapY, n }; });
  const columns = Math.max(...data.nodes.map((n) => n.column)) + 1;
  const rows = Math.max(...data.nodes.map((n) => n.row)) + 1;
  const width = pad * 2 + W + (columns - 1) * gapX, height = pad * 2 + H + (rows - 1) * gapY;

  const out = {}, into = {};
  data.edges.forEach((e) => {
    if (e.source === e.target) return;
    (out[e.source] = out[e.source] || []).push(e);
    (into[e.target] = into[e.target] || []).push(e);
  });
  Object.values(out).forEach((l) => l.sort((a, b) => at[a.target].y - at[b.target].y));
  Object.values(into).forEach((l) => l.sort((a, b) => at[a.source].y - at[b.source].y));
  const fan = (list, e) => ((list.indexOf(e) + 1) / (list.length + 1) - 0.5) * H * 0.8;
  const biggest = Math.max(1, ...data.edges.map((e) => e.execs));

  const lines = data.edges.map((e) => {
    const a = at[e.source], b = at[e.target];
    const stroke = (1.1 + 3 * Math.sqrt(e.execs / biggest)).toFixed(1);
    const cls = e.status !== "same" ? e.status : e.root ? "root" : "";
    let d, lx, ly;
    if (e.source === e.target) {
      const cx = a.x + W / 2;
      d = `M${cx + 28} ${a.y} C${cx + 34} ${a.y - 32} ${cx - 34} ${a.y - 32} ${cx - 28} ${a.y}`;
      lx = cx; ly = a.y - 28;
    } else if (b.x > a.x) {
      const x1 = a.x + W, y1 = a.y + H / 2 + fan(out[e.source], e), x2 = b.x - 3, y2 = b.y + H / 2 + fan(into[e.target], e);
      const span = (x2 - x1) * 0.48;
      d = `M${x1} ${y1} C${x1 + span} ${y1} ${x2 - span} ${y2} ${x2} ${y2}`;
      // In the gap after the source, so a long arrow's label never lands on a
      // box it passes over.
      const gap = gapX - W, s = Math.min(0.5, (gap * 0.5) / (x2 - x1)), u = 1 - s;
      lx = u * u * u * x1 + 3 * u * u * s * (x1 + span) + 3 * u * s * s * (x2 - span) + s * s * s * x2;
      ly = u * u * u * y1 + 3 * u * u * s * y1 + 3 * u * s * s * y2 + s * s * s * y2 - 3;
    } else {
      const x1 = a.x, y1 = a.y + H / 2, x2 = b.x + W + 3, y2 = b.y + H / 2, lift = Math.max(70, Math.abs(x1 - x2) * 0.4);
      if (a.x === b.x) {
        const rx = a.x + W, side = rx + 42;
        d = `M${rx} ${y1} C${side} ${y1} ${side} ${y2} ${rx + 3} ${y2}`;
        lx = side - 8; ly = (y1 + y2) / 2;
      } else {
        d = `M${x1} ${y1} C${x1 - lift} ${y1 - lift * 0.55} ${x2 + lift} ${y2 - lift * 0.55} ${x2} ${y2}`;
        lx = (x1 + x2) / 2; ly = (y1 + y2) / 2 - lift * 0.42;
      }
    }
    let label = `${e.runs} run${e.runs === 1 ? "" : "s"}`;
    if (e.execs > e.runs) label += ` · ${e.execs} tries`;
    if (e.status === "added") label = `+${e.after} added`;
    if (e.status === "removed") label = `${e.before} removed`;
    if (e.status === "changed") label = `${e.before} → ${e.after}`;
    const tip = `${e.source} → ${e.target}\n${e.runs} process(es), ${e.execs} exec attempt(s)${e.root ? "\nran as root" : ""}${e.status !== "same" ? `\nattack: ${e.status}` : ""}`;
    return { path: `<path class="gedge ${cls}" d="${d}" stroke-width="${stroke}" marker-end="url(#a-${cls || "plain"})" data-tip="${esc(tip)}"/>`,
             label, lx, ly };
  });

  // Keep labels in the same gap at least one line apart.
  const placed = [];
  [...lines].sort((a, b) => a.ly - b.ly).forEach((l) => {
    let y = l.ly;
    while (placed.some((p) => Math.abs(p.x - l.lx) < 96 && Math.abs(p.y - y) < 14)) y += 14;
    placed.push({ x: l.lx, y });
    l.text = `<text class="glabel" x="${l.lx}" y="${y}" text-anchor="middle">${esc(l.label)}</text>`;
  });

  const marker = (id, colour) => `<marker id="a-${id}" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" markerUnits="userSpaceOnUse" orient="auto"><path d="M0 0 10 5 0 10z" fill="${colour}"/></marker>`;
  const boxes = data.nodes.map((n) => {
    const p = at[n.name];
    const title = n.name.length > 20 ? `${n.name.slice(0, 19)}…` : n.name;
    const sub = n.kind === "external" ? "already running" : `${n.starts} exec${n.starts === 1 ? "" : "s"}`;
    return `<g class="gnode ${n.kind}${n.flagged ? " flagged" : ""}" tabindex="0" role="button" data-node="${esc(n.name)}" aria-label="${esc(`${n.name}, ${sub}`)}">
      <rect x="${p.x}" y="${p.y}" width="${W}" height="${H}" rx="6"/>
      <text class="t1" x="${p.x + W / 2}" y="${p.y + 24}" text-anchor="middle">${esc(title)}</text>
      <text class="t2" x="${p.x + W / 2}" y="${p.y + 42}" text-anchor="middle">${esc(sub)}</text></g>`;
  }).join("");

  return `<div class="graphbox"><svg viewBox="0 0 ${width} ${height}" style="width:100%;max-width:${width}px;min-width:${Math.round(width * 0.62)}px;height:auto;margin:auto" role="img" aria-label="Which program ran which">
    <defs>${marker("plain", "#5a7183")}${marker("root", "#ff8f6b")}${marker("added", "#ff6464")}${marker("removed", "#f4b740")}${marker("changed", "#2fd4e8")}</defs>
    ${lines.map((l) => l.path).join("")}${boxes}${lines.map((l) => l.text).join("")}</svg></div>`;
}

function graphLegend(data, diff) {
  const has = (k) => data.nodes.some((n) => n.kind === k);
  const items = [
    has("user") && ['<i style="border-color:#3f9bd6;background:#10283b"></i>', "ran as a user"],
    has("root") && ['<i style="border-color:var(--root);background:#3a1a14"></i>', "ran as root"],
    has("external") && ['<i style="border-color:var(--faint);border-style:dashed"></i>', "started before the capture"],
    data.nodes.some((n) => n.flagged) && ['<i style="border-color:var(--warn)"></i>', "flagged by the GNN"],
    diff && ['<i class="line" style="border-color:var(--bad)"></i>', "added by the attack"],
    diff && ['<i class="line" style="border-color:var(--warn);border-top-style:dashed"></i>', "removed by the attack"],
    diff && ['<i class="line" style="border-color:var(--signal)"></i>', "count changed"],
  ].filter(Boolean);
  return `<div class="legend">${items.map(([i, t]) => `<span>${i}${esc(t)}</span>`).join("")}</div>`;
}

function bindGraph(root, data, detail) {
  const select = (g) => {
    $$(".gnode", root).forEach((n) => n.classList.remove("sel"));
    g.classList.add("sel");
    const node = data.nodes.find((n) => n.name === g.dataset.node);
    if (!node || !detail) return;
    const info = node.detail;
    const calls = data.edges.filter((e) => e.source === node.name || e.target === node.name);
    detail.innerHTML = `<h3 class="mono">${esc(node.name)}</h3>
      ${info ? `<dl class="kv"><dt>Execs</dt><dd>${node.starts}</dd><dt>Processes</dt><dd>${info.processes}</dd><dt>User IDs</dt><dd>${esc(info.uids.join(", "))}</dd></dl>
      <h4>Paths tried</h4><div class="tablewrap"><table><tbody>${info.paths.map(([p, n]) => `<tr><td class="mono path">${esc(p)}</td><td class="num">${n}</td></tr>`).join("")}</tbody></table></div>`
        : "<p class='note'>This program was already running when capture began, so only the programs it started are recorded.</p>"}
      <h4>Calls</h4><div class="tablewrap"><table><tbody>${calls.map((e) => `<tr><td>${esc(e.source)} → ${esc(e.target)}</td><td class="num">${e.execs}</td></tr>`).join("")}</tbody></table></div>`;
  };
  $$(".gnode", root).forEach((g) => {
    g.addEventListener("click", () => select(g));
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(g); } });
  });
}

function chain(partitions) {
  if (!partitions.length) return empty("No partitions.");
  const flag = (name, ok) => `<span class="${ok ? "y" : "n"}">${ok ? "✓" : "✕"} ${name}</span>`;
  return `<div class="chain">${partitions.map((p) => {
    const index = p.index ?? p.partition_index;
    const ok = p.signature_ok && p.record_hash_ok && p.chain_ok && p.merkle_ok;
    return `<div class="block ${ok ? "" : "bad"}"><b>Partition ${index}</b>
      <span class="hash">seq ${p.start ?? p.seq_start}–${p.end ?? p.seq_end}${p.leaves ? ` · ${p.leaves} leaves` : ""}</span>
      ${p.root ? `<div class="hash" data-tip="${esc(`Merkle root\n${p.root}`)}">root ${short(p.root, 10)}</div>` : ""}
      <div class="checks">${flag("signature", p.signature_ok)}${flag("hash", p.record_hash_ok)}${flag("chain", p.chain_ok)}${flag("merkle", p.merkle_ok)}</div></div>`;
  }).join("")}</div>`;
}

const tierChip = (tier) => {
  const c = (tier || "").startsWith("tier1") ? "t1" : (tier || "").startsWith("tier2") ? "t2" : "t3";
  const text = { t1: "tier 1 immediate", t2: "tier 2 batched", t3: "tier 3 local" }[c];
  return `<span class="tier ${c}">${text}</span>`;
};

/* ------------------------------------------------------------- views */

async function viewOverview(box, alive) {
  const d = await api("/api/overview");
  if (!alive()) return;
  const s = d.stats, det = d.detection;
  const verified = d.verified;
  const detail = det ? `${det.rule_violations} rule hits · ${det.gnn_flagged} GNN flags` : "build a graph first";
  box.innerHTML = `
  <section class="hero" aria-label="Current status">
    <div class="tile"><div class="label">EVIDENCE INTEGRITY</div>
      <div class="big ${verified == null ? "idle" : verified ? "ok" : "fail"}">${verified == null ? "NOT SEALED" : verified ? "VERIFIED" : "FAILED"}</div>
      <small>${s.partitions} sealed partitions · ${s.ledger_blocks} ledger blocks</small></div>
    <div class="tile"><div class="label">DETECTION VERDICT</div>
      <div class="big ${verdictKind(det?.verdict)}">${esc(det?.verdict || "NO GRAPH")}</div><small>${esc(detail)}</small></div>
    <div class="tile"><div class="label">CAPTURE</div>
      <div class="big ${d.running ? "signal" : "idle"}">${d.running ? "RECORDING" : "STOPPED"}</div>
      <small>${s.events} events · ${s.lost} attested lost · ${s.root_events} as root</small></div>
    <div class="tile"><div class="label">SURVIVABILITY INDEX</div>
      <div class="big ${s.fsi == null ? "idle" : "signal"}">${s.fsi == null ? "N/A" : `${s.fsi.toFixed(1)}%`}</div>
      <small>${esc(d.phases[6].note)}</small></div>
  </section>
  <section class="panel"><div class="panel-head"><h3>Pipeline</h3><span class="note">Select a phase for detail</span></div>
    <ol class="flow">${d.phases.map((p, i) => `<li><a href="#${p.key}" class="${p.state}"><span class="n">PHASE ${i + 1}</span><b>${esc(p.title)}</b>
      <span class="v">${esc(p.value)}</span><small>${esc(p.note)}</small></a></li>`).join("")}</ol></section>
  <div class="grid g2">
    <section class="panel"><h3>Advisories</h3>${d.advisories.length ? d.advisories.map((a) => {
      const kind = { critical: "s-fail", warn: "s-warn", info: "s-active" }[a.level];
      const icon = { critical: "✕", warn: "▲", info: "i" }[a.level];
      const colour = { critical: "var(--bad)", warn: "var(--warn)", info: "var(--signal)" }[a.level];
      return `<div class="advisory" data-kind="${kind}"><i style="color:${colour}">${icon}</i><b>${esc(a.title)}</b><p>${esc(a.text)}</p></div>`;
    }).join("") : `<p>${state("ok", "NO OPEN ADVISORIES")}</p>`}</section>
    <section class="panel"><h3>Defence scorecard</h3>${d.tamper ? `
      <div class="bar-row"><span>Seal, all attacks</span><span class="bar-track"><span class="bar-fill" style="width:${d.tamper.seal * 100}%"></span></span><span class="num mono">${pct(d.tamper.seal)}</span></div>
      <div class="bar-row"><span>Verdict, trained attacks</span><span class="bar-track"><span class="bar-fill" style="width:${d.tamper.trained_fusion * 100}%"></span></span><span class="num mono">${pct(d.tamper.trained_fusion)}</span></div>
      <div class="bar-row"><span>Verdict, unseen attacks</span><span class="bar-track"><span class="bar-fill" style="width:${d.tamper.held_fusion * 100}%"></span></span><span class="num mono">${pct(d.tamper.held_fusion)}</span></div>
      <div class="bar-row"><span>False alarms on clean</span><span class="bar-track"><span class="bar-fill" style="width:${d.tamper.clean_false * 100}%"></span></span><span class="num mono">${pct(d.tamper.clean_false)}</span></div>
      <p class="note">Last saved test, synthetic graphs. ${d.tamper.evidence_caught} of ${d.tamper.evidence_total} evidence attacks caught. <a href="#scorecard">Open the scorecard</a></p>`
      : empty("No tamper test has been saved.", "python main.py tamper test --trials 30")}</section>
  </div>
  <section class="panel"><div class="panel-head"><h3>Try an attack</h3><span class="badge sandbox">SANDBOX</span></div>
    <p class="note">Attack a copy of your evidence and watch which layer notices. Your real graph, keys and ledger are never changed.</p>
    <p style="margin:12px 0 0"><a href="#lab"><button tabindex="-1">Open Attack Lab</button></a> <a href="#pipeline"><button class="ghost" tabindex="-1">Run the full pipeline</button></a></p></section>`;
}

async function viewCapture(box, alive, _a, refresh) {
  const d = await api("/api/capture");
  if (!alive()) return;
  const filter = refresh ? ($("#evfilter")?.value || "") : "";
  box.innerHTML = `
  <section class="hero">
    <div class="tile"><div class="label">STATUS</div><div class="big ${d.running ? "signal" : "idle"}">${d.running ? "RECORDING" : "STOPPED"}</div><small>Store: ${esc(d.backend)}</small></div>
    <div class="tile"><div class="label">EVENTS</div><div class="big">${d.total}</div><small>${d.sessions.length} capture session(s)</small></div>
    <div class="tile"><div class="label">ATTESTED LOST</div><div class="big ${d.missing_count ? "warn" : "ok"}">${d.missing_count}</div><small>Recorded by CCA, so not deletion</small></div>
    <div class="tile"><div class="label">ROOT EVENTS</div><div class="big ${d.root_events ? "signal" : "warn"}">${d.root_events}</div><small>${d.root_events ? "Root activity is being recorded" : "Run sudo ls during a capture to test"}</small></div>
  </section>
  ${d.timeline.length > 1 ? `<section class="panel"><h3>Events per minute</h3>${timeline(d.timeline)}</section>` : ""}
  <div class="grid g3">
    <section class="panel"><h3>Top callers</h3>${d.by_caller.length ? bars(d.by_caller) : empty("No events yet.")}</section>
    <section class="panel"><h3>By user ID</h3>${d.by_uid.length ? bars(d.by_uid) : empty("No events yet.")}</section>
    <section class="panel"><h3>Start a capture</h3><p class="note">Capture needs your <code>sudo</code> password, so it runs in a terminal. Events appear here as they arrive.</p>
      <p style="margin:10px 0 0"><code>python main.py capture</code></p></section>
  </div>
  <section class="panel"><div class="panel-head"><h3>Latest events</h3>
    <div class="field"><label for="evfilter">FILTER</label><input id="evfilter" type="search" placeholder="program or path" value="${esc(filter)}"></div></div>
    ${d.events.length ? `<div class="tablewrap"><table><thead><tr><th class="num">SEQ</th><th>TIME</th><th class="num">PID</th><th class="num">UID</th><th>CALLER</th><th>PROGRAM</th></tr></thead><tbody id="evrows">
    ${d.events.map((e) => `<tr data-search="${esc(`${e.comm} ${e.file}`.toLowerCase())}"><td class="num mono">${e.seq}</td><td class="mono">${e.ts > 1e18 ? new Date(e.ts / 1e6).toLocaleTimeString() : "before wall clock"}</td><td class="num mono">${e.pid}</td><td class="num mono">${e.uid}</td><td>${esc(e.comm)}</td><td class="mono path">${esc(e.file)}</td></tr>`).join("")}</tbody></table></div>` : empty("No events captured yet.", "python main.py capture")}</section>
  <section class="panel"><h3>Capture sessions</h3><div class="tablewrap"><table><thead><tr><th>SESSION</th><th>STARTED (UTC)</th><th>ENDED (UTC)</th><th class="num">LAST SEQ</th></tr></thead><tbody>
    ${d.sessions.map((s) => `<tr><td class="mono">${esc(s.run)}</td><td class="mono">${esc(s.started.slice(0, 19))}</td><td class="mono">${s.ended ? esc(s.ended.slice(0, 19)) : "no end recorded"}</td><td class="num mono">${s.last ?? ""}</td></tr>`).join("") || '<tr><td colspan="4">None</td></tr>'}</tbody></table></div></section>`;
  const input = $("#evfilter");
  const apply = () => {
    const q = input.value.trim().toLowerCase();
    $$("#evrows tr").forEach((r) => { r.hidden = !!q && !r.dataset.search.includes(q); });
  };
  input?.addEventListener("input", apply);
  if (filter) apply();
}

async function viewGraph(box, alive) {
  const d = await api("/api/graph");
  if (!alive()) return;
  if (!d) { box.innerHTML = empty("No graph has been built yet.", "python main.py graph"); return; }
  box.innerHTML = `<p class="lede">One box per program, merged from ${d.graph_nodes} nodes and ${d.graph_edges} relations. A run is one process. Tries include each PATH lookup. Select a box for its paths and calls.${d.hidden ? ` ${d.hidden} rarer calls are not drawn.` : ""}${d.folded ? ` ${d.folded} rarer programs are grouped.` : ""}</p>
  <section class="panel" id="gpanel">${graphSvg(d)}${graphLegend(d)}</section>
  <section class="panel" id="gdetail"><h3>Program detail</h3><p class="note">Select a program in the graph.</p></section>`;
  bindGraph($("#gpanel"), d, $("#gdetail"));
}

function detectionBody(d) {
  const rules = Object.entries(d.rules);
  return `<div class="grid g3">
    <div class="vcard ${d.verdict === "CLEAN" ? "hit" : d.verdict === "TAMPERED" ? "miss" : "maybe"}"><div class="label">VERDICT</div><b>${esc(d.verdict)}</b>
      <small>${{ CLEAN: "No rule fired and the GNN did not alert.", SUSPICIOUS: "Only the GNN alerted. This is not proof, so check the seal.", TAMPERED: "A rule found proof of inconsistency." }[d.verdict]}</small></div>
    <div class="vcard"><div class="label">RULE ENGINE</div><b>${d.rule_violations} hits</b><small>Checks that always hold for an honest graph.</small></div>
    <div class="vcard"><div class="label">GRAPHSAGE MODEL</div><b>${d.model_loaded ? `${d.gnn_flagged} flagged` : "NOT TRAINED"}</b><small>${d.model_loaded ? `Node score at or above ${d.threshold.toFixed(3)}. An alert needs 2 nodes.` : "Run: python main.py train"}</small></div>
  </div>
  ${d.larger_than_training ? `<p class="note">${state("warn", "LARGE CAPTURE")} ${d.events} events is more than the model trained on, so its false alarms are likely.</p>` : ""}
  <div class="grid g2" style="margin-top:16px">
    <section class="panel"><h3>Rules</h3><div class="tablewrap"><table><thead><tr><th>RULE</th><th>SEVERITY</th><th class="num">HITS</th></tr></thead><tbody>
      ${rules.map(([r, sev]) => `<tr><td class="mono">${esc(r)}</td><td>${esc(sev)}</td><td class="num">${d.by_rule[r] ? `<b>${d.by_rule[r]}</b>` : "0"}</td></tr>`).join("")}</tbody></table></div></section>
    <section class="panel"><h3>Most suspicious nodes</h3>${d.suspicious.length ? `<div class="tablewrap"><table><thead><tr><th>NODE</th><th class="num">SCORE</th></tr></thead><tbody>
      ${d.suspicious.map((n) => `<tr><td class="mono path">${esc(n.node)}</td><td class="num mono">${n.score.toFixed(3)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="note">The model flagged no nodes.</p>`}
      ${d.violations.length ? `<h4>Rule findings</h4><div class="tablewrap"><table><tbody>${d.violations.slice(0, 12).map((v) => `<tr><td class="mono">${esc(v.rule)}</td><td>${esc(v.detail)}</td></tr>`).join("")}</tbody></table></div>` : ""}</section></div>`;
}

async function viewDetection(box, alive) {
  const d = await api("/api/detection");
  if (!alive()) return;
  box.innerHTML = d ? detectionBody(d) : empty("No graph has been built yet.", "python main.py graph");
}

async function viewSeal(box, alive) {
  const d = await api("/api/seal");
  if (!alive()) return;
  if (!d.run) { box.innerHTML = empty("Nothing has been sealed yet.", "python main.py seal"); return; }
  const v = d.verification;
  box.innerHTML = `
  <section class="hero">
    <div class="tile"><div class="label">VERIFICATION</div><div class="big ${v.ok ? "ok" : "fail"}">${v.ok ? "PASS" : "FAIL"}</div><small>Latest run, against the current graph</small></div>
    <div class="tile"><div class="label">SIGNATURES</div><div class="big signal">HYBRID</div><small>Ed25519 and ${esc(d.algorithm)}. Both must pass.</small></div>
    <div class="tile"><div class="label">LEDGER</div><div class="big ${v.ledger_ok ? "ok" : "fail"}">${v.ledger_blocks} blocks</div><small>${v.cross_check.length ? "Disagrees with sealed evidence" : "Agrees with sealed evidence"}</small></div>
    <div class="tile"><div class="label">SIGNER</div><div class="big ${v.pinned ? "ok" : "warn"}">${v.pinned ? "PINNED" : "NOT PINNED"}</div><small class="mono">${esc(short(v.signer, 20))}</small></div>
  </section>
  ${v.errors.length ? `<section class="error"><b>What failed</b><ul>${v.errors.slice(0, 8).map((e) => `<li>${esc(e)}</li>`).join("")}</ul></section>` : ""}
  <section class="panel"><div class="panel-head"><h3>Hash chain</h3><span class="note mono">run ${esc(short(d.run, 8))} · format ${d.format} · ${d.runs} run(s) stored</span></div>
    ${chain(d.partitions)}<p class="note">Each partition stores the hash of the one before it and the total count, so deleting, reordering or truncating partitions breaks verification.</p></section>
  <section class="panel"><h3>Completeness certificates</h3>${v.certificates.length ? `<div class="tablewrap"><table><thead><tr><th>FILE</th><th>SIGNATURE</th><th>RANGE</th><th class="num">OBSERVED</th><th class="num">LOST</th></tr></thead><tbody>
    ${v.certificates.map((c) => `<tr><td class="mono">${esc(c.name)}</td><td>${c.ok ? state("ok", "VALID") : state("fail", "INVALID")}</td><td class="mono">${c.start}–${c.end}</td><td class="num">${c.observed}</td><td class="num">${c.missing}</td></tr>`).join("")}</tbody></table></div>
    <p class="note">A certificate covers events that reached the collector. An event the probe never saw cannot appear as lost.</p>` : empty("No certificates yet. One is written when a capture stops.")}</section>`;
}

async function viewAnchoring(box, alive) {
  const d = await api("/api/anchoring");
  if (!alive()) return;
  const r = d.report;
  if (!r) { box.innerHTML = empty("Nothing has been anchored yet.", "python main.py anchor"); return; }
  const t = r.summary.by_tier;
  box.innerHTML = `
  <section class="hero">
    <div class="tile"><div class="label">TIER 1 IMMEDIATE</div><div class="big ${t.tier1_immediate ? "fail" : ""}">${t.tier1_immediate || 0}</div><small>Anchored to the ledger at once</small></div>
    <div class="tile"><div class="label">TIER 2 BATCHED</div><div class="big ${t.tier2_batched ? "warn" : ""}">${t.tier2_batched || 0}</div><small>Share one transaction</small></div>
    <div class="tile"><div class="label">TIER 3 LOCAL</div><div class="big">${t.tier3_local || 0}</div><small>Hash chain only, no cost</small></div>
    <div class="tile"><div class="label">LEDGER TRANSACTIONS</div><div class="big signal">${r.ledger_transactions}</div><small>For ${r.summary.partitions} partitions</small></div>
  </section>
  <div class="grid g-side">
    <section class="panel"><h3>Risk per partition</h3>${riskChart(r.scores, d.tier1, d.tier2)}
      <details style="margin-top:10px"><summary>Show as a table</summary><div class="tablewrap"><table><thead><tr><th>PARTITION</th><th class="num">SCORE</th><th>TIER</th><th>ESCALATED BY</th><th>SEQUENCE</th></tr></thead><tbody>
      ${r.scores.map((s) => `<tr><td>${s.partition_index}</td><td class="num mono">${s.risk_score.toFixed(3)}</td><td>${tierChip(s.risk_tier)}</td><td>${esc(s.escalated_by || "score")}</td><td class="mono">${s.seq_start}–${s.seq_end}</td></tr>`).join("")}</tbody></table></div></details></section>
    <section class="panel"><h3>Signal weights</h3>${Object.entries(d.weights).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<div class="bar-row"><span>${esc(k.replace(/_/g, " "))}</span><span class="bar-track"><span class="bar-fill" style="width:${v * 400}%"></span></span><span class="num mono">${v.toFixed(2)}</span></div>`).join("")}
      <p class="note">A policy choice, written down so an auditor can disagree with it.</p></section>
  </div>
  <section class="panel"><h3>Ledger blocks</h3>${d.blocks.length ? `<div class="tablewrap"><table><thead><tr><th class="num">BLOCK</th><th>TIME (UTC)</th><th>KIND</th><th class="num">PARTITIONS</th><th>ROOT</th><th>BLOCK HASH</th></tr></thead><tbody>
    ${d.blocks.map((b) => `<tr><td class="num">${b.number}</td><td class="mono">${esc(String(b.time).slice(0, 19))}</td><td>${esc(b.kind)}</td><td class="num">${b.members}</td><td class="mono" data-tip="${esc(b.root)}">${short(b.root)}</td><td class="mono" data-tip="${esc(b.hash)}">${short(b.hash)}</td></tr>`).join("")}</tbody></table></div>
    <p class="note">This ledger is a local file that imitates a blockchain. A real Hyperledger Fabric network is what would stop a root attacker replacing it.</p>` : empty("The ledger is empty: no partition has scored high enough to anchor.")}</section>`;
}

/* ------------------------------------------------------------- attack lab */

let catalogueCache = null;
async function getCatalogue() {
  catalogueCache = catalogueCache || await api("/api/catalogue");
  return catalogueCache;
}
const attackOptions = (attacks, selected) => [["held_out", "Never seen by the model"], ["trained", "Seen in training"]].map(([family, label]) =>
  `<optgroup label="${label}">${attacks.filter((a) => a.family === family).map((a) => `<option value="${esc(a.name)}" ${a.name === selected ? "selected" : ""}>${esc(a.name.replace(/_/g, " "))}</option>`).join("")}</optgroup>`).join("");

function segmented(id, options, value) {
  return `<div class="seg" id="${id}" role="group">${options.map(([v, t]) => `<button type="button" data-v="${v}" aria-pressed="${v === value}">${esc(t)}</button>`).join("")}</div>`;
}
function bindSegmented(id) {
  const root = document.getElementById(id);
  $$("button", root).forEach((b) => b.addEventListener("click", () => {
    $$("button", root).forEach((x) => x.setAttribute("aria-pressed", x === b));
  }));
  return () => $('[aria-pressed="true"]', root).dataset.v;
}

async function viewLab(box, alive, action) {
  const c = await getCatalogue();
  if (!alive()) return;
  box.innerHTML = `
  <p class="lede">Seals a copy of the graph, applies one attack, then runs the real detector, verifier and risk model against it. The sandbox is deleted afterwards.</p>
  <section class="panel"><h3>Attack on the graph</h3><div class="controls">
    <div class="field"><label for="atk">ATTACK</label><select id="atk">${attackOptions(c.attacks, "adaptive_forgery")}</select></div>
    <div class="field"><span class="lbl">EVIDENCE</span>${segmented("src", [["real", "My capture"], ["synthetic", "Synthetic"]], "real")}</div>
    <div class="field"><label for="int">INTENSITY <span id="intv">10%</span></label><input id="int" type="range" min="2" max="50" value="10"></div>
    <div class="field"><label for="seed">SEED</label><input id="seed" type="number" min="0" value="7"></div>
    <button id="run">Launch attack</button></div>
    <p class="note" id="atkdesc"></p></section>
  <div id="labout"></div>
  <section class="panel"><div class="panel-head"><h3>Attacks on the sealed records and ledger</h3><button class="ghost" id="runev">Run all evidence attacks</button></div>
    <p class="note">These leave the graph alone and change the signed records and the ledger. Every one should be caught.</p><div id="evout"></div></section>`;
  const getSource = bindSegmented("src");
  const atk = $("#atk"), desc = () => { $("#atkdesc").textContent = c.attacks.find((a) => a.name === atk.value)?.description || ""; };
  atk.addEventListener("change", desc); desc();
  $("#int").addEventListener("input", (e) => { $("#intv").textContent = `${e.target.value}%`; });
  const run = async () => {
    const out = $("#labout"), button = $("#run");
    button.disabled = true;
    out.innerHTML = '<div class="loading">Sealing a copy and running the attack</div>';
    try {
      const r = await api("/api/simulate/attack", { attack: atk.value, source: getSource(), intensity: +$("#int").value / 100, seed: +$("#seed").value });
      if (alive()) renderLab(out, r);
    } catch (e) { out.innerHTML = `<div class="error">${esc(e.message)}</div>`; }
    button.disabled = false;
  };
  const runEvidence = async () => {
    const out = $("#evout"), button = $("#runev");
    button.disabled = true;
    out.innerHTML = '<div class="loading">Attacking the sealed records</div>';
    try {
      const r = await api("/api/simulate/evidence", {});
      if (alive()) out.innerHTML = evidenceTable(r.attacks);
    } catch (e) { out.innerHTML = `<div class="error">${esc(e.message)}</div>`; }
    button.disabled = false;
  };
  $("#run").addEventListener("click", run);
  $("#runev").addEventListener("click", runEvidence);
  if (action === "run") { run(); runEvidence(); }
}

function evidenceTable(items) {
  const caught = items.filter((i) => i.detected).length;
  return `<p>${caught === items.length ? state("ok", `${caught} OF ${items.length} CAUGHT`) : state("fail", `${items.length - caught} MISSED`)}</p>
  <div class="tablewrap"><table><thead><tr><th>ATTACK</th><th>LAYER</th><th>RESULT</th><th>WHY</th></tr></thead><tbody>
  ${items.map((i) => `<tr><td>${esc(i.attack)}</td><td class="mono">${esc(i.layer)}</td><td>${i.detected ? state("ok", "CAUGHT") : state("fail", "MISSED")}</td><td class="mono path">${esc(i.reason || "")}</td></tr>`).join("")}</tbody></table></div>`;
}

function renderLab(out, r) {
  const L = r.layers, verdict = r.detection.verdict;
  const card = (label, caught, big, text, maybe) => `<div class="vcard ${maybe ? "maybe" : caught ? "hit" : "miss"}"><div class="label">${label}</div><b>${big}</b><small>${esc(text)}</small></div>`;
  const noisy = r.clean.verdict !== "CLEAN";
  const rules = Object.entries(L.rules.by_rule);
  out.innerHTML = `<div class="grid" style="gap:16px">
  <section class="panel"><div class="panel-head"><h3>Who noticed</h3><span class="note mono">${esc(r.attack)} · ${r.family === "trained" ? "seen in training" : "never seen in training"} · ${r.nodes_changed} nodes changed</span></div>
    <div class="grid g4">
      ${card("RULES", L.rules.caught, L.rules.caught ? "CAUGHT" : "MISSED", L.rules.caught ? rules.map(([k, v]) => `${k}: ${v}`).join(", ") : "No high or critical rule fired.")}
      ${card("GNN MODEL", L.gnn.caught, !L.gnn.model ? "NO MODEL" : L.gnn.caught ? "ALERTED" : "MISSED", `${L.gnn.flagged} nodes above ${L.gnn.threshold.toFixed(2)}.`, L.gnn.caught && noisy)}
      ${card("REPORTED VERDICT", verdict !== "CLEAN", esc(verdict), { CLEAN: "The attack was not detected.", SUSPICIOUS: "A suspicion, not proof.", TAMPERED: "Backed by a rule." }[verdict], verdict === "SUSPICIOUS")}
      ${card("SEAL", L.seal.caught, L.seal.caught ? "PROVEN" : "MISSED", L.seal.caught ? `${r.seal.missing_leaves} sealed relations gone or edited, ${r.seal.inserted} unsealed added.` : "The graph still matches its seal.")}
    </div>
    ${noisy ? `<p class="note">${state("warn", "READ THE GNN RESULT WITH CARE")} This graph was already ${esc(r.clean.verdict)} before the attack (${r.clean.gnn_flagged} GNN flags), so a GNN alert here does not show it saw the attack.</p>` : ""}</section>
  <section class="panel"><h3>What the attack changed</h3>${r.graph.changed ? "" : '<p class="note">No change at program level: this attack altered timing or attributes, not who ran what.</p>'}${graphSvg(r.graph)}${graphLegend(r.graph, true)}</section>
  <div class="grid g2">
    <section class="panel"><h3>Seal verification</h3>${chain(r.seal.partitions)}${r.seal.error_count ? `<p class="note">${r.seal.error_count} failed checks.</p>` : ""}</section>
    <section class="panel"><h3>Risk response</h3>${riskChart(r.anchor.scores, 0.45, 0.2)}<p class="note">${r.anchor.summary.by_tier.tier1_immediate || 0} partitions escalated to tier 1, using ${r.anchor.transactions} ledger transaction(s).</p></section>
  </div></div>`;
}

/* ------------------------------------------------------------- pipeline */

async function viewPipeline(box, alive, action) {
  const c = await getCatalogue();
  if (!alive()) return;
  box.innerHTML = `<p class="lede">Runs all seven phases in order. Only the kernel is simulated: exec events go through the real CCA, graph builder, detector, sealing, anchoring and survivability code, with throwaway keys.</p>
  <section class="panel"><div class="controls">
    <div class="field"><label for="pev">EVENTS</label><input id="pev" type="number" min="30" max="300" value="120"></div>
    <div class="field"><label for="ploss">LOST IN RING BUFFER</label><input id="ploss" type="number" min="0" max="25" value="3"></div>
    <div class="field"><label for="patk">ATTACK</label><select id="patk">${attackOptions(c.attacks, "forgery_expert")}</select></div>
    <div class="field"><label for="pseed">SEED</label><input id="pseed" type="number" min="0" value="7"></div>
    <button id="prun">Run pipeline</button></div></section><div id="pout"></div>`;
  const run = async () => {
    const out = $("#pout"), button = $("#prun");
    button.disabled = true;
    out.innerHTML = '<div class="loading">Running all phases</div>';
    try {
      const r = await api("/api/simulate/pipeline", { events: +$("#pev").value, loss: +$("#ploss").value, attack: $("#patk").value, seed: +$("#pseed").value });
      if (alive()) await renderPipeline(out, r, alive);
    } catch (e) { out.innerHTML = `<div class="error">${esc(e.message)}</div>`; }
    button.disabled = false;
  };
  $("#prun").addEventListener("click", run);
  if (action === "run") run();
}

function stepExtra(s) {
  if (s.key === "attack" && s.graph) return `${graphSvg(s.graph)}${graphLegend(s.graph, true)}`;
  if (s.key === "graph" && s.graph) return `<details><summary>Show the graph</summary>${graphSvg(s.graph)}${graphLegend(s.graph)}</details>`;
  if (s.seal) return chain(s.seal.partitions);
  if (s.anchor) return riskChart(s.anchor.scores, 0.45, 0.2);
  if (s.survival) return `<div class="grid g4">${Object.entries(s.survival).filter(([k]) => k !== "FSI").map(([k, v]) => `<div class="vcard"><div class="label">${k}</div><b>${v.toFixed(1)}%</b></div>`).join("")}</div>`;
  return "";
}

async function renderPipeline(out, r, alive) {
  const sealed = r.seal_caught, verdict = r.verdict;
  out.innerHTML = `<section class="panel"><ol class="steps" id="steps"></ol><div id="psum"></div></section>`;
  const list = $("#steps");
  const icon = { ok: "✓", fail: "!", warn: "▲", miss: "–" };
  for (const [i, s] of r.steps.entries()) {
    if (!alive()) return;
    const li = document.createElement("li");
    li.innerHTML = `<div class="dot ${s.state}" aria-hidden="true">${icon[s.state] || i + 1}</div><div>
      <div class="step-head"><b>${esc(s.title)}</b><span>${s.ms} ms</span></div>
      <div class="log">${s.lines.map(esc).join("<br>")}</div>${stepExtra(s) ? `<div class="step-extra">${stepExtra(s)}</div>` : ""}</div>`;
    list.appendChild(li);
    if (!reduced) await new Promise((done) => setTimeout(done, 240));
  }
  $("#psum").innerHTML = `<div class="grid g3"><div class="vcard ${verdict === "CLEAN" ? "miss" : verdict === "SUSPICIOUS" ? "maybe" : "hit"}"><div class="label">DETECTOR</div><b>${esc(verdict)}</b><small>${r.family === "trained" ? "An attack the model trained on." : "An attack the model never saw."}</small></div>
    <div class="vcard ${sealed ? "hit" : "miss"}"><div class="label">SEAL</div><b>${sealed ? "PROVEN" : "MISSED"}</b><small>Hash and signature check against the seal made before the attack.</small></div>
    <div class="vcard ${r.ledger_ok ? "hit" : "miss"}"><div class="label">LEDGER</div><b>${r.ledger_blocks} blocks</b><small>${r.ledger_ok ? "Chain and signatures verify." : "Ledger verification failed."}</small></div></div>`;
}

/* ------------------------------------------------------------- survivability */

const METRICS = { PIS: "Integrity Score", EPR: "Preservation Ratio", GRR: "Recovery Rate", RA: "Recovery Accuracy", FSI: "Survivability Index" };
const METRIC_HELP = { PIS: "Sealed relations still present and matching", EPR: "Captured events still present", GRR: "Causal paths that can still be walked", RA: "Of what is called authentic, how much really is", FSI: "The four measures combined" };

async function viewSurvivability(box, alive) {
  const d = await api("/api/survivability");
  if (!alive()) return;
  box.innerHTML = `<p class="lede">Damages a copy of the graph and measures what evidence an investigator still has. Detection asks if there was an attack. This asks what is left afterwards.</p>
  <section class="panel"><div class="controls">
    <div class="field"><label for="smode">DAMAGE TYPE</label><select id="smode">${d.modes.map((m) => `<option ${m === "mixed" ? "selected" : ""}>${esc(m)}</option>`).join("")}</select></div>
    <div class="field"><label for="srat">DAMAGE <span id="sratv">25%</span></label><input id="srat" type="range" min="0" max="90" value="25"></div>
    <div class="field"><span class="lbl">EVIDENCE</span>${segmented("ssrc", d.has_graph ? [["real", "My capture"], ["synthetic", "Synthetic"]] : [["synthetic", "Synthetic"]], d.has_graph ? "real" : "synthetic")}</div>
    <button id="srun">Measure</button></div></section><div id="sout"></div>`;
  const getSource = bindSegmented("ssrc");
  $("#srat").addEventListener("input", (e) => { $("#sratv").textContent = `${e.target.value}%`; });
  const run = async () => {
    const out = $("#sout"), button = $("#srun");
    button.disabled = true;
    try {
      const r = await api("/api/simulate/survivability", { mode: $("#smode").value, ratio: +$("#srat").value / 100, source: getSource() });
      if (!alive()) return;
      const b = r.benefit, e = r.evidence;
      out.innerHTML = `<div class="grid" style="gap:16px"><div class="grid g3">
        ${["FSI", "PIS", "EPR", "GRR", "RA"].map((k) => `<section class="panel"><div class="metric-head"><span>${k} · ${METRICS[k]}</span><b>${r.metrics[k].toFixed(1)}%</b></div>${lineChart(r.curve, k, { label: METRICS[k] })}<p class="note">${METRIC_HELP[k]}. X axis: damage.</p></section>`).join("")}
        <section class="panel"><h3>What can be proven</h3><dl class="kv"><dt>Sealed relations</dt><dd>${e.sealed_relations}</dd><dt>Verified intact</dt><dd>${e.verified_intact}</dd><dt>Provably deleted</dt><dd>${e.provably_deleted}</dd><dt>Unsealed, present</dt><dd>${e.unsealed_present}</dd><dt>GRR upper bound</dt><dd>${r.grr_bridged.toFixed(1)}%</dd></dl>
        <p class="note">The upper bound needs the original graph, which an investigator would not have, so FSI does not use it.</p></section></div>
        <section class="panel"><h3>What sealing is worth</h3><div class="tablewrap"><table><thead><tr><th></th>${Object.keys(METRICS).map((k) => `<th class="num">${k}</th>`).join("")}</tr></thead><tbody>
          <tr><td>With the seal</td>${Object.keys(METRICS).map((k) => `<td class="num mono">${b.with_sealing[k].toFixed(1)}</td>`).join("")}</tr>
          <tr><td>Without the seal</td>${Object.keys(METRICS).map((k) => `<td class="num mono">${b.without_sealing[k].toFixed(1)}</td>`).join("")}</tr></tbody></table></div>
          <p class="note">${b.fabricated_relations ? `${b.fabricated_relations} fabricated relations. Accuracy gain from sealing: ${b.ra_gain.toFixed(1)} points. With the seal, RA is 100% by construction, so the measurement is the figure without it.` : "This damage type adds nothing fake, so RA does not separate the two."}</p></section></div>`;
    } catch (e) { out.innerHTML = `<div class="error">${esc(e.message)}</div>`; }
    button.disabled = false;
  };
  $("#srun").addEventListener("click", run);
  run();
}

/* ------------------------------------------------------------- scorecard */

function heat(value) {
  if (value == null) return '<td class="heat">n/a</td>';
  const alpha = (0.08 + value * 0.62).toFixed(2);
  return `<td class="heat" style="background:rgba(47,212,232,${alpha})">${Math.round(value * 100)}%</td>`;
}

function scoreTable(source) {
  const row = (name, r) => `<tr><td class="mono">${esc(name.replace(/_/g, " "))}</td><td class="num mono">${r.trials}</td>${heat(r.rules)}${heat(r.gnn)}${heat(r.fusion)}${heat(r.seal)}</tr>`;
  const family = (key) => Object.entries(source.attacks).filter(([, r]) => r.family === key).map(([n, r]) => row(n, r)).join("");
  const c = source.clean;
  const alarm = (v) => `<td class="heat" style="${v ? `background:var(--warn-bg);color:var(--warn)` : ""}">${Math.round(v * 100)}%</td>`;
  return `<div class="tablewrap"><table><thead><tr><th>ATTACK</th><th class="num">GRAPHS</th><th class="heat">RULES</th><th class="heat">GNN</th><th class="heat">VERDICT</th><th class="heat">SEAL</th></tr></thead><tbody>
    <tr class="band"><td colspan="6">FALSE ALARMS ON CLEAN GRAPHS (LOWER IS BETTER)</td></tr>
    <tr><td>clean</td><td class="num mono">${c.trials}</td>${alarm(c.rules)}${alarm(c.gnn)}${alarm(c.fusion)}${alarm(c.seal)}</tr>
    <tr class="band"><td colspan="6">ATTACKS SEEN IN TRAINING</td></tr>${family("trained")}
    <tr class="band"><td colspan="6">ATTACKS NEVER SEEN IN TRAINING</td></tr>${family("held_out")}</tbody></table></div>`;
}

function renderScores(out, r, origin) {
  const sources = Object.entries(r.sources);
  const whole = r.sources.real?.whole_capture;
  out.innerHTML = `<div class="grid" style="gap:16px">
    <p class="note">${esc(origin)}. Threshold ${r.threshold.toFixed(3)}, attack intensity ${Math.round(r.intensity * 100)}%. Darker cells caught more.${r.model_loaded ? "" : " No trained model, so the GNN column means nothing."}</p>
    <div class="grid g2">${sources.map(([name, s]) => `<section class="panel"><h3>${name === "real" ? "My capture" : "Synthetic graphs"} (${s.graphs})</h3>${scoreTable(s)}
      ${name === "real" ? `<p class="note">Scores here are optimistic if the model trained on this capture.${whole ? ` As a whole, this capture gets the verdict ${esc(whole.verdict)}.` : ""}</p>` : ""}</section>`).join("")}</div>
    <section class="panel"><h3>Attacks on the sealed records and ledger</h3>${evidenceTable(r.evidence_attacks)}</section></div>`;
}

async function viewScorecard(box, alive, action) {
  box.innerHTML = `<p class="lede">Runs every attack against every layer and scores each layer alone. Results stay in this session and do not replace your saved report.</p>
  <section class="panel"><div class="controls">
    <div class="field"><label for="ctr">GRAPHS PER ATTACK</label><input id="ctr" type="number" min="1" max="60" value="20"></div>
    <div class="field"><label for="cint">INTENSITY <span id="cintv">10%</span></label><input id="cint" type="range" min="2" max="50" value="10"></div>
    <button id="crun">Run scorecard</button></div><div id="cprog"></div></section><div id="cout"></div>`;
  $("#cint").addEventListener("input", (e) => { $("#cintv").textContent = `${e.target.value}%`; });
  const out = $("#cout");
  const poll = async () => {
    const button = $("#crun"), bar = $("#cprog");
    if (!button) return;
    const job = await api("/api/scorecard/job");
    if (!alive()) return;
    if (job.state === "running") {
      button.disabled = true;
      bar.innerHTML = `<p class="note mono">${esc(job.label)} (${job.done} of ${job.total})</p><div class="progress"><span style="width:${(job.done / Math.max(1, job.total)) * 100}%"></span></div>`;
      setTimeout(poll, 700);
      return;
    }
    button.disabled = false;
    bar.innerHTML = "";
    if (job.state === "done") renderScores(out, job.result, `This session: ${job.trials} synthetic graphs per attack`);
    if (job.state === "failed") out.innerHTML = `<div class="error">${esc(job.error)}</div>`;
    return job.state;
  };
  $("#crun").addEventListener("click", async () => {
    try {
      await api("/api/scorecard/start", { trials: +$("#ctr").value, intensity: +$("#cint").value / 100 });
      poll();
    } catch (e) { out.innerHTML = `<div class="error">${esc(e.message)}</div>`; }
  });
  if (action === "run") { await api("/api/scorecard/start", { trials: +$("#ctr").value, intensity: 0.1 }); poll(); return; }
  const status = await poll();
  if (status === "idle" || status === undefined) {
    const saved = await api("/api/scorecard/saved");
    if (!alive() || status === undefined) return;
    if (saved) renderScores(out, saved, "Last saved test");
    else out.innerHTML = empty("No results yet. Select Run scorecard.");
  }
}

/* ------------------------------------------------------------- shell */

function buildNav() {
  $("#nav").innerHTML = VIEWS.map((v) => v.group ? `<h2>${v.group}</h2>` : `<a href="#${v.id}" data-id="${v.id}">${esc(v.label)}</a>`).join("");
  $("#sidefoot").innerHTML = "Live views only read your data. Simulations run in a temporary sandbox with throwaway keys.";
}

const tip = $("#tip");
function placeTip(event) {
  const x = Math.min(event.clientX + 14, innerWidth - tip.offsetWidth - 8);
  const y = Math.min(event.clientY + 14, innerHeight - tip.offsetHeight - 8);
  tip.style.left = `${x}px`;
  tip.style.top = `${y}px`;
}
document.addEventListener("mouseover", (e) => {
  const target = e.target.closest?.("[data-tip]");
  if (!target) { tip.hidden = true; return; }
  tip.textContent = target.dataset.tip;
  tip.hidden = false;
  placeTip(e);
});
document.addEventListener("mousemove", (e) => { if (!tip.hidden) placeTip(e); });

setInterval(() => { $("#clock").textContent = new Date().toLocaleTimeString(); }, 1000);
$("#clock").textContent = new Date().toLocaleTimeString();
buildNav();
window.addEventListener("hashchange", route);
route();
