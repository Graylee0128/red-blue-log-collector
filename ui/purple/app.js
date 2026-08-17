/* Purple Console -- 涵蓋率表 / 動作下鑽 / Exercise Report。
 *
 * 骨架搬自 cyber 的 ui/purple/app.js（issue #3）。砍掉的部分：Action
 * Registry（register/freeze——rbcollector 沒有預先註冊的動作清單，只有
 * 觀察到的事件）以及配套的「未凍結前不顯示」限制。涵蓋率表直接依
 * src/rbcollector/detections.py 幫每一列 /analysis correlation 標的
 * `technique` 分組——永遠有東西可以顯示，只是可能多一個「(unclassified)」
 * 桶，裝沒有規則命中的紅隊事件。
 */

import { Api, humanize, $, $$, el, clear, renderEmpty, showBanner, poll } from "../assets/api.js";

const api = new Api();
const banner = $("#banner");

const state = {
  analysis: null,      // /analysis 原始回應
  groups: new Map(),   // technique -> correlation 列
  selected: null,
};

const UNCLASSIFIED = "(unclassified)";

const STATUS_BADGE = {
  hit:             { class: "detected", label: "✅ hit" },
  detection_gap:   { class: "missed",   label: "❌ detection gap" },
  visibility_gap:  { class: "unknown",  label: "⏳ visibility gap" },
};

/** 用「最壞的那個」狀態代表一個技法的列——只要有一個 miss，這個技法就算
 *  沒被涵蓋，跟 cyber 的 worstState() 同一條規則。 */
function worstStatus(rows) {
  for (const candidate of ["detection_gap", "visibility_gap", "hit"]) {
    if (rows.some((r) => r.status === candidate)) return candidate;
  }
  return "hit";
}

async function refresh() {
  try {
    state.analysis = await api.analysis();
    showBanner(banner, "");
    groupByTechnique();
    render();
  } catch (error) {
    showBanner(banner, humanize(error));
  }
}

function groupByTechnique() {
  const groups = new Map();
  for (const row of state.analysis.correlations ?? []) {
    const key = row.technique ?? UNCLASSIFIED;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }
  state.groups = groups;
}

function render() {
  $("#subtitle").textContent = `${state.analysis.red_actions} red action(s) observed`;
  renderCoverage();
  renderMetrics();
  renderReport();
  if (state.selected) renderDrilldown(state.selected);
}

/* ---------- 畫面一：涵蓋率表 ---------- */

function renderCoverage() {
  const body = clear($("#coverage-rows"));
  if (state.groups.size === 0) {
    renderEmpty($("#coverage-empty"), "No red-team actions observed yet.");
    return;
  }
  clear($("#coverage-empty"));

  for (const [technique, rows] of state.groups) {
    const status = worstStatus(rows);
    const badge = STATUS_BADGE[status];
    const row = el("tr", { class: "clickable" }, [
      el("td", { text: technique }),
      el("td", { text: String(rows.length) }),
      el("td", {}, [el("span", { class: `badge ${badge.class}`, text: badge.label })]),
    ]);
    row.addEventListener("click", () => openDrilldown(technique));
    body.append(row);
  }
}

function renderMetrics() {
  const host = clear($("#coverage-metrics"));
  const a = state.analysis;
  const percent = (v) => (v === null || v === undefined ? "—" : `${(v * 100).toFixed(1)}%`);
  for (const [label, value] of [
    ["Detection rate", percent(a.detection_rate)],
    ["Detected", String(a.detected)],
    ["Detection gaps", String(a.detection_gaps)],
    ["Visibility gaps", String(a.visibility_gaps)],
    ["MTTD p50", a.mttd_p50_ms === null ? "—" : `${a.mttd_p50_ms}ms`],
    ["MTTD p95", a.mttd_p95_ms === null ? "—" : `${a.mttd_p95_ms}ms`],
  ]) {
    host.append(el("div", { class: "metric" }, [
      el("div", { class: "label", text: label }),
      el("div", { class: "value", text: value }),
    ]));
  }
}

/* ---------- 畫面二：動作下鑽 ---------- */

function openDrilldown(technique) {
  state.selected = technique;
  renderDrilldown(technique);
  showScreen("drilldown");
}

function renderDrilldown(technique) {
  const panel = clear($("#drilldown-panel"));
  const rows = state.groups.get(technique) ?? [];

  panel.append(el("div", { style: "font-size:18px;font-weight:600", text: technique }));

  if (rows.length === 0) {
    panel.append(el("div", { class: "empty", text: "No actions for this technique." }));
    return;
  }

  for (const row of rows) {
    const badge = STATUS_BADGE[row.status] ?? { class: "neutral", label: row.status };
    panel.append(el("div", { class: "section-label", text: `Red event ${row.red?.event_id ?? "—"}` }));
    panel.append(el("div", { class: "kv-row" }, [
      el("span", { class: "k", text: "Red action" }),
      el("span", { text: row.red?.message || "—" }),
    ]));
    panel.append(el("div", { class: "kv-row" }, [
      el("span", { class: "k", text: "Status" }),
      el("span", { class: `badge ${badge.class}`, text: badge.label }),
    ]));
    panel.append(el("div", { class: "kv-row" }, [
      el("span", { class: "k", text: "Matched blue event" }),
      el("span", { text: row.blue?.message || "—" }),
    ]));
    panel.append(el("div", { class: "kv-row" }, [
      el("span", { class: "k", text: "Latency" }),
      el("span", { text: row.latency_ms === null || row.latency_ms === undefined ? "—" : `${row.latency_ms}ms` }),
    ]));
    panel.append(el("div", { class: "kv-row" }, [
      el("span", { class: "k", text: "Evidence" }),
      el("span", {}, [
        row.red?.event_id
          ? el("button", { class: "link mono", text: "view context", onclick: () => showEvidence(row.red.event_id) })
          : el("span", { text: "—" }),
      ]),
    ]));
  }
}

async function showEvidence(eventId) {
  try {
    const bundle = await api.context(eventId, "purple");
    const lines = (bundle.lines ?? [])
      .map((line) => `${line.observed_at}  [${line.team}]  ${JSON.stringify(line.payload)}`)
      .join("\n");
    window.alert(
      `Event ${bundle.event_id}\n${bundle.line_count} line(s) within ±${bundle.window_minutes}min\n\n`
      + (lines || "(no context lines)")
    );
  } catch (error) {
    showBanner(banner, humanize(error));
  }
}

/* ---------- Exercise Report ---------- */

function renderReport() {
  const host = clear($("#report-body"));
  const a = state.analysis;

  const row = (key, value) => el("div", { class: "kv-row" }, [
    el("span", { class: "k", text: key }),
    el("span", { text: value }),
  ]);

  host.append(row("Red actions", String(a.red_actions)));
  host.append(row("Detected", String(a.detected)));

  const gapRows = (a.correlations ?? []).filter((r) => r.status !== "hit");
  const gapList = el("div");
  if (gapRows.length === 0) {
    gapList.append(el("div", { class: "empty", text: "No gaps -- everything observed was detected." }));
  } else {
    for (const r of gapRows) {
      const badge = STATUS_BADGE[r.status] ?? { class: "neutral", label: r.status };
      gapList.append(el("div", { class: "kv-row" }, [
        el("span", { class: "k", text: r.technique ?? UNCLASSIFIED }),
        el("span", {}, [el("span", { class: `badge ${badge.class}`, text: badge.label })]),
      ]));
    }
  }
  host.append(el("div", { class: "section-label", text: "Gaps" }));
  host.append(gapList);
}

/* ---------- 分頁 ---------- */

function showScreen(name) {
  for (const section of ["coverage", "drilldown", "report"]) {
    $(`#screen-${section}`).hidden = section !== name;
  }
  for (const tab of $$(".tab")) {
    tab.classList.toggle("active", tab.dataset.screen === name);
  }
}

for (const tab of $$(".tab")) {
  tab.addEventListener("click", () => showScreen(tab.dataset.screen));
}
$("#back-to-coverage").addEventListener("click", () => showScreen("coverage"));

poll(10, refresh);
