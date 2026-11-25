(() => {
  "use strict";

  const $ = (s, el = document) => el.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = new Intl.NumberFormat("en-US");
  const compact = new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 2 });

  const TACTIC_COLORS = {
    "credential-access": ["#7a1f0b", "#ff7a1a"],
    "stealth": ["#5a4314", "#ffb020"],
    "defense-impairment": ["#6b3410", "#ff9442"],
    "persistence": ["#4b3a0e", "#ffd166"],
    "privilege-escalation": ["#6a2a18", "#ff8a65"],
    "execution": ["#5c3c08", "#f6c453"],
    "lateral-movement": ["#3e3216", "#e8c27a"],
    "discovery": ["#2f3640", "#b8c4d2"],
    "command-and-control": ["#4a2c0e", "#ffa94d"],
    "collection": ["#3b3320", "#d9c08c"],
    "initial-access": ["#5b1d16", "#ff6b5b"],
  };
  const PRODUCT_LABEL = { windows: "Windows", linux: "Linux", aws: "AWS" };

  const state = { data: null, platform: "all", query: "", technique: null };
  // ?still (screenshots) or reduced motion: render the final state with no load animation
  const STILL = new URLSearchParams(location.search).has("still") || matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (STILL) document.documentElement.classList.add("still");

  fetch("data/dashboard.json", { cache: "no-cache" })
    .then((r) => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then((d) => { state.data = d; render(); })
    .catch((e) => {
      $("#rule-list").innerHTML = `<div class="empty">Could not load data/dashboard.json (${esc(e.message)}). Run <code>python -m picket all</code> first.</div>`;
    });

  function render() {
    const d = state.data;
    $("#attack-ver").textContent = `ATT&CK v${d.attack_version}`;
    $("#built").textContent = d.generated;
    const c = $("#commit");
    c.textContent = d.commit;
    c.href = `${d.repo}/commit/${d.commit}`;
    renderCounts();
    renderFence();
    renderStats();
    renderMatrix();
    renderChips();
    renderRules();
    renderPipeline();
    renderDatasets();
    bindDrawer();
    $("#search").addEventListener("input", (e) => { state.query = e.target.value.trim().toLowerCase(); renderRules(); });
    const deep = new URLSearchParams(location.search).get("rule");
    if (deep && d.rules.some((r) => r.slug === deep)) openRule(deep);
  }

  /* ---------- hero counters ---------- */
  function renderCounts() {
    const s = state.data.summary;
    document.querySelectorAll(".count").forEach((el, i) => {
      const target = s[el.dataset.key] ?? 0;
      const isCompact = el.dataset.format === "compact";
      const show = (v) => (isCompact ? compact.format(v) : fmt.format(Math.round(v)));
      const start = performance.now() + i * 120;
      const dur = 1400;
      const tick = (now) => {
        const t = Math.min(1, Math.max(0, (now - start) / dur));
        const e = 1 - Math.pow(1 - t, 4);
        el.textContent = show(target * e);
        if (t < 1) requestAnimationFrame(tick);
      };
      if (STILL) { el.textContent = show(target); return; }
      el.textContent = show(0);
      requestAnimationFrame(tick);
    });
  }

  /* ---------- the fence ---------- */
  function ruleHits(r) {
    return r.positives.reduce((a, p) => a + p.hits, 0) + Object.values(r.other_attack_hits || {}).reduce((a, b) => a + b, 0);
  }
  function renderFence() {
    const rules = [...state.data.rules];
    const max = Math.log10(Math.max(...rules.map(ruleHits)) + 1);
    const fence = $("#fence");
    const hover = $("#fence-hover");
    fence.innerHTML = rules.map((r, i) => {
      const h = 22 + 78 * (Math.log10(ruleHits(r) + 1) / max);
      const [c1, c2] = TACTIC_COLORS[r.tactics[0]] || ["#3a3f47", "#c0c8d2"];
      return `<button class="picket" style="--h:${h.toFixed(1)}%;--c1:${c1};--c2:${c2};--d:${(i * 38)}ms" data-slug="${esc(r.slug)}" aria-label="${esc(r.title)}"></button>`;
    }).join("");
    fence.addEventListener("mouseover", (e) => {
      const b = e.target.closest(".picket");
      if (!b) return;
      const r = state.data.rules.find((x) => x.slug === b.dataset.slug);
      hover.innerHTML = `<b>${esc(r.title)}</b> · ${fmt.format(ruleHits(r))} attack events`;
    });
    fence.addEventListener("click", (e) => {
      const b = e.target.closest(".picket");
      if (b) openRule(b.dataset.slug);
    });
  }

  /* ---------- stats ---------- */
  function renderStats() {
    const s = state.data.summary;
    const conv = s.conversions || {};
    const det = s.scenarios ? (s.scenarios_detected / s.scenarios) * 100 : 0;
    const fpRate = s.benign_events ? (s.fp_total / s.benign_events) * 100 : 0;
    const cells = [
      { k: "Attack scenarios detected", v: `${s.scenarios_detected}<small>/ ${s.scenarios}</small>`, sub: `${det.toFixed(0)}% detection across ${s.datasets} datasets`, bar: det },
      { k: "Benign false-positive rate", v: `${fpRate.toFixed(5)}<small>%</small>`, sub: `${s.fp_total} hits over ${fmt.format(s.benign_events)} clean events`, bar: 100 - Math.min(100, fpRate * 1000) },
      { k: "ATT&CK techniques covered", v: `${s.techniques}`, sub: `${s.parent_techniques} parent techniques across ${s.tactics} of ${s.tactic_total} tactics`, bar: (s.tactics / s.tactic_total) * 100 },
      { k: "Backends converted", v: `${conv.splunk ? conv.splunk.converted : 0}<small>SPL</small> ${conv.elastic ? conv.elastic.converted : 0}<small>ES</small> ${conv.kql ? conv.kql.converted : 0}<small>KQL</small>`, sub: "pySigma conversions per rule", bar: conv.kql ? ((conv.splunk.converted + conv.elastic.converted + conv.kql.converted) / (3 * conv.splunk.total)) * 100 : 0 },
    ];
    $("#stats").innerHTML = cells.map((c, i) => `
      <div class="stat" style="animation-delay:${200 + i * 90}ms">
        <div class="k">${c.k}</div>
        <div class="v">${c.v}</div>
        <div class="sub">${c.sub}</div>
        <div class="bar"><i data-w="${c.bar.toFixed(1)}"></i></div>
      </div>`).join("");
    requestAnimationFrame(() => setTimeout(() => document.querySelectorAll(".bar i").forEach((b) => { b.style.width = b.dataset.w + "%"; }), 60));
  }

  /* ---------- ATT&CK matrix ---------- */
  function renderMatrix() {
    const d = state.data;
    const s = d.summary;
    $("#cov-note").textContent = `${s.parent_techniques} of ${s.matrix_parent_total} Enterprise techniques have at least one tested rule. Coverage is deliberately narrow and deep: each lit cell is backed by a replayed attack, not just a tag.`;
    let k = 0;
    $("#matrix").innerHTML = d.matrix.map((t) => {
      const cells = t.techniques.map((c) => {
        const n = c.rules.length;
        const lvl = n === 0 ? "" : n === 1 ? "l1" : n === 2 ? "l2" : "l3";
        const delay = (k++ % 400) * 2;
        return `<span class="cell ${lvl} ${n ? "on" : ""}" style="--d:${delay}ms" data-t="${esc(c.id)}" data-tac="${esc(t.short)}" ${n ? 'tabindex="0" role="button"' : ""} aria-label="${esc(c.id)} ${esc(c.name)}${n ? `, ${n} rules` : ""}"></span>`;
      }).join("");
      return `<div class="tac">
        <div class="tac-name">${esc(t.name)}<small>${esc(t.id)} · ${t.techniques.length} techniques</small></div>
        <div class="cells">${cells}</div>
        <div class="tac-score"><b>${t.covered}</b> / ${t.techniques.length}</div>
      </div>`;
    }).join("");

    const tip = $("#tooltip");
    const find = (el) => {
      const tac = d.matrix.find((m) => m.short === el.dataset.tac);
      return tac.techniques.find((c) => c.id === el.dataset.t);
    };
    const show = (el, x, y) => {
      const c = find(el);
      const rules = c.rules.map((slug) => d.rules.find((r) => r.slug === slug));
      tip.innerHTML = `<div class="tid">${esc(c.id)}${c.subs ? ` · ${c.subs} sub-techniques` : ""}</div><div>${esc(c.name)}</div>` +
        (c.covered.length ? `<ul>${c.covered.map((x) => `<li>${esc(x.id)} ${esc(x.name)}</li>`).join("")}</ul>` : "") +
        (rules.length ? `<ul>${rules.map((r) => `<li style="color:#eef2f6">${esc(r.title)}</li>`).join("")}</ul>` : `<ul><li>No rule yet</li></ul>`);
      const w = 320;
      tip.style.left = Math.min(window.innerWidth - w - 12, x + 14) + "px";
      tip.style.top = Math.min(window.innerHeight - tip.offsetHeight - 12, y + 14) + "px";
      tip.classList.add("show");
    };
    const m = $("#matrix");
    m.addEventListener("mousemove", (e) => { const el = e.target.closest(".cell"); if (el) show(el, e.clientX, e.clientY); else tip.classList.remove("show"); });
    m.addEventListener("mouseleave", () => tip.classList.remove("show"));
    const pick = (el) => {
      if (!el || !el.classList.contains("on")) return;
      const c = find(el);
      state.technique = state.technique && state.technique.id === c.id ? null : c;
      document.querySelectorAll(".cell.sel").forEach((x) => x.classList.remove("sel"));
      if (state.technique) document.querySelectorAll(`.cell[data-t="${c.id}"]`).forEach((x) => x.classList.add("sel"));
      renderRules();
      if (state.technique) $("#rules").scrollIntoView({ behavior: "smooth" });
    };
    m.addEventListener("click", (e) => pick(e.target.closest(".cell")));
    m.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(e.target.closest(".cell")); } });
  }

  /* ---------- rules ---------- */
  function renderChips() {
    const counts = {};
    state.data.rules.forEach((r) => { counts[r.product] = (counts[r.product] || 0) + 1; });
    const opts = [["all", `All ${state.data.rules.length}`], ...Object.entries(counts).map(([p, n]) => [p, `${PRODUCT_LABEL[p] || p} ${n}`])];
    const el = $("#platform-chips");
    el.innerHTML = opts.map(([v, l]) => `<button class="chip ${v === state.platform ? "on" : ""}" data-v="${v}">${esc(l)}</button>`).join("");
    el.addEventListener("click", (e) => {
      const b = e.target.closest(".chip");
      if (!b) return;
      state.platform = b.dataset.v;
      el.querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c === b));
      renderRules();
    });
  }

  function matches(r) {
    if (state.platform !== "all" && r.product !== state.platform) return false;
    if (state.technique && !state.technique.rules.includes(r.slug)) return false;
    if (!state.query) return true;
    const hay = [r.title, r.slug, r.logsource, r.product, ...r.techniques, ...Object.values(r.technique_names), ...r.tactics, r.queries.splunk || ""].join(" ").toLowerCase();
    return hay.includes(state.query);
  }

  function renderRules() {
    const af = $("#active-filter");
    if (state.technique) {
      af.hidden = false;
      af.innerHTML = `Showing rules for <b>${esc(state.technique.id)} ${esc(state.technique.name)}</b> <button type="button">clear</button>`;
      af.querySelector("button").onclick = () => { state.technique = null; document.querySelectorAll(".cell.sel").forEach((x) => x.classList.remove("sel")); renderRules(); };
    } else af.hidden = true;

    const rows = state.data.rules.filter(matches);
    const head = `<div class="rule-row head"><div>Rule</div><div>Technique</div><div>Level</div><div>Attack scenarios</div><div>Benign FP</div><div style="justify-self:end">Replay</div></div>`;
    if (!rows.length) { $("#rule-list").innerHTML = head + `<div class="empty">No rules match.</div>`; return; }
    $("#rule-list").innerHTML = head + rows.map((r) => {
      const t = r.techniques[0];
      const dots = r.positives.map((p) => `<i class="${p.passed ? "" : "miss"} ${p.source === "fixture" ? "fx" : ""}" title="${esc(p.dataset)}: ${p.hits} hits"></i>`).join("");
      const fpCls = r.fp === 0 ? "zero" : "some";
      return `<div class="rule-row" data-slug="${esc(r.slug)}" tabindex="0" role="button">
        <div class="rule-title">${esc(r.title)}<small>${esc(PRODUCT_LABEL[r.product] || r.product)} · ${esc(r.logsource)} · ${esc(r.slug)}</small></div>
        <div class="tech"><b>${esc(t)}</b> ${esc(r.technique_names[t])}${r.techniques.length > 1 ? ` <span style="color:var(--faint)">+${r.techniques.length - 1}</span>` : ""}</div>
        <div><span class="lvl ${esc(r.level)}">${esc(r.level)}</span></div>
        <div class="scen">${dots}<span>${r.detected}/${r.scenarios}</span></div>
        <div class="fp ${fpCls}">${r.fp}<small> / ${r.fp_budget} budget</small></div>
        <div class="res ${r.passed ? "pass" : "fail"}">${r.passed ? "PASS" : "FAIL"}</div>
      </div>`;
    }).join("");
  }

  /* ---------- drawer ---------- */
  function bindDrawer() {
    $("#rule-list").addEventListener("click", (e) => { const row = e.target.closest(".rule-row[data-slug]"); if (row) openRule(row.dataset.slug); });
    $("#rule-list").addEventListener("keydown", (e) => { if (e.key === "Enter") { const row = e.target.closest(".rule-row[data-slug]"); if (row) openRule(row.dataset.slug); } });
    document.querySelectorAll("[data-close]").forEach((el) => el.addEventListener("click", closeDrawer));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  }
  function closeDrawer() {
    const dr = $("#drawer");
    dr.classList.remove("open");
    dr.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
  }
  function openRule(slug) {
    const r = state.data.rules.find((x) => x.slug === slug);
    const rate = r.benign_events ? ((r.fp / r.benign_events) * 100) : 0;
    const backends = [["splunk", "Splunk SPL"], ["elastic", "Elastic Lucene"], ["kql", "Defender KQL"]];
    const first = backends.find(([k]) => r.queries[k]);
    $("#drawer-body").innerHTML = `
      <div class="d-eyebrow">${esc(PRODUCT_LABEL[r.product] || r.product)} · ${esc(r.logsource)} · ${esc(r.level)}</div>
      <h3 class="d-title" id="d-title">${esc(r.title)}</h3>
      <div class="d-tags">${r.techniques.map((t) => `<span class="t">${esc(t)} ${esc(r.technique_names[t])}</span>`).join("")}${r.tactics.map((t) => `<span>${esc(t)}</span>`).join("")}</div>
      <div class="d-grid">
        <div><div class="k">Scenarios</div><div class="v">${r.detected}/${r.scenarios}</div></div>
        <div><div class="k">Benign FP</div><div class="v">${r.fp} <small style="font-size:13px;color:var(--faint)">/ ${r.fp_budget}</small></div></div>
        <div><div class="k">FP rate</div><div class="v">${rate === 0 ? "0" : rate.toFixed(4)}%</div></div>
      </div>
      <div class="d-h">Attack scenarios replayed</div>
      <table class="d-table">${r.positives.map((p) => `<tr><td>${esc(p.dataset)}<span class="src">${esc(p.source)}</span></td><td class="${p.passed ? "ok" : "no"}">${p.hits} hit${p.hits === 1 ? "" : "s"} / ${fmt.format(p.events || 0)} ev</td></tr>`).join("")}</table>
      ${Object.keys(r.other_attack_hits).length ? `<div class="d-h">Also fired on other attack captures</div><table class="d-table">${Object.entries(r.other_attack_hits).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join("")}</table>` : ""}
      <div class="d-h">Benign replay · ${fmt.format(r.benign_events)} events from this log source</div>
      ${r.fp_samples.length ? r.fp_samples.map((s) => `<div class="fp-sample">${Object.entries(s).map(([k, v]) => `<div><b style="color:var(--text)">${esc(k)}</b> ${esc(v)}</div>`).join("")}</div>`).join("") : `<div class="fp-sample" style="color:var(--mint)">No benign events matched.</div>`}
      <div class="d-h">Converted queries</div>
      <div class="tabs">${backends.map(([k, l]) => `<button class="tab ${k === (first && first[0]) ? "on" : ""} ${r.queries[k] ? "" : "na"}" data-k="${k}">${l}</button>`).join("")}</div>
      <pre class="code" id="q"></pre>
      <div class="d-links">
        <a class="btn primary" href="${esc(r.doc_url)}" target="_blank" rel="noopener">Read the write-up ↗</a>
        <a class="btn" href="${esc(r.source_url)}" target="_blank" rel="noopener">Sigma YAML ↗</a>
      </div>`;
    const showQ = (k) => {
      const q = r.queries[k];
      const pre = $("#q");
      pre.textContent = q || `Not converted: ${r.query_errors[k] || "unsupported"}`;
      if (q) {
        const b = document.createElement("button");
        b.className = "copy"; b.textContent = "copy";
        b.onclick = () => navigator.clipboard.writeText(q).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1200); }).catch(() => { b.textContent = "select + copy"; });
        pre.appendChild(b);
      }
      document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("on", t.dataset.k === k));
    };
    document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => showQ(t.dataset.k)));
    showQ(first ? first[0] : "splunk");
    const dr = $("#drawer");
    dr.classList.add("open");
    dr.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
    $(".drawer-panel").scrollTop = 0;
  }

  /* ---------- pipeline ---------- */
  function renderPipeline() {
    const s = state.data.summary;
    const c = s.conversions || {};
    const attackDs = state.data.datasets.filter((d) => d.kind === "attack").length;
    const benignDs = state.data.datasets.filter((d) => d.kind === "benign").length;
    const stages = [
      ["Author", "Sigma YAML per rule with ATT&CK tags, false positives and a write-up next to it.", `${s.rules} rules`],
      ["Lint", "pySigma's 30 validators plus house rules: technique tag, references, replay case, docs.", "0 problems to merge"],
      ["Convert", "pySigma backends with Sysmon, ECS and Defender XDR field pipelines.", `SPL ${c.splunk?.converted ?? 0} · ES ${c.elastic?.converted ?? 0} · KQL ${c.kql?.converted ?? 0}`],
      ["Fetch", "Script pulls OTRF, EVTX-ATTACK-SAMPLES and Nextron baselines, normalises to JSONL.", `${attackDs} attack · ${benignDs} benign sets`],
      ["Replay", "A small Sigma engine evaluates each rule's condition tree over every event.", `${compact.format(s.attack_events + s.benign_events)} events in ${s.seconds}s`],
      ["Assert + publish", "Every scenario detected, FP within budget, or CI fails. Then this page and the Navigator layer ship.", `${s.passed}/${s.rules} rules pass`],
    ];
    $("#pipe").innerHTML = stages.map(([h, p, m], i) => `<div class="stage"><div class="n">0${i + 1}</div><h3>${h}</h3><p>${p}</p><div class="metric">${esc(m)}</div><span class="flow" style="--d:${i * 0.45}s"></span></div>`).join("");
  }

  /* ---------- datasets ---------- */
  function renderDatasets() {
    const ds = state.data.datasets;
    const groups = [
      ["OTRF Security-Datasets", "MIT · Mordor captures of real tooling (Empire, Covenant, Atomic Red Team)", ds.filter((d) => d.source === "otrf")],
      ["EVTX-ATTACK-SAMPLES", "GPL-3.0 · Windows event logs of individual techniques", ds.filter((d) => d.source === "evtx")],
      ["Benign baselines", "Nextron evtx-baseline (Apache-2.0) clean Windows 10 and Server 2022 AD, plus synthetic Linux/AWS/look-alike fixtures", ds.filter((d) => d.kind === "benign")],
    ];
    $("#datasets").innerHTML = groups.map(([name, meta, list]) => {
      const total = list.reduce((a, d) => a + (d.events || 0), 0);
      return `<div class="ds-card"><h3>${esc(name)}</h3><div class="meta">${esc(meta)}</div>
        <div class="big">${fmt.format(total)} <small>events · ${list.length} sets</small></div>
        <ul>${list.sort((a, b) => (b.events || 0) - (a.events || 0)).map((d) => `<li><span>${esc(d.id)}</span><b>${fmt.format(d.events || 0)}</b></li>`).join("")}</ul></div>`;
    }).join("");
  }
})();
