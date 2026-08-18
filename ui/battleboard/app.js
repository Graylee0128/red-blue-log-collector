/* Battleboard -- 公開層。教室大螢幕，所有人都看得到。
 *
 * 骨架搬自 cyber 的 ui/battleboard/app.js（issue #3）。每一個限制都是
 * 刻意的，跟原始設計一致：
 *
 * 1. **技法一律標成 `Attack #N`**。真正的 ATT&CK 編號不上公開牆——要看
 *    去紫隊 Console。
 * 2. **只渲染 `hit` 這一種列**。detection_gap／visibility_gap 依
 *    src/rbcollector/disclosure.py 是 `purple`-only；就算標成「尚未偵測」
 *    顯示在這裡，也等於在紫隊/教官正式公布前先洩漏「這個技法有沒有被
 *    打穿」。還沒（或永遠不會）變成公開命中的項目，一律顯示成同一種
 *    中性的「pending」圓點——這個畫面本來就不該讓人分辨得出「還在
 *    進行中」跟「漏掉了」的差別。
 * 3. **不放沒有分母的裸百分比**——「已偵測」用 `X / Y` 分數形式呈現，
 *    對應 `/analysis` 本來就會回的彙總數字（這是整場演練的彙總，不是
 *    針對單一技法的判定，所以不像 #2 那樣有洩漏風險）。
 *
 * 相對 cyber 整段砍掉的：`#153` Campaign Experience Layer（章節橫幅、
 * cue toast、音效）——那是 cyber 場景／戰役系統的裝飾層，rbcollector
 * 沒有這個概念。也砍掉 Range Core 的 `/api/score` 紅藍積分——rbcollector
 * 沒有計分系統，這裡改顯示 detection_rate／MTTD 而非積分總和。SSE
 * live 串流也砍了，改用這裡到處都在用的同一套 5 秒輪詢，因為
 * rbcollector 沒有 `/api/events/live` 這個端點。
 */

import { Api, humanize, $, el, clear, showBanner, clockTime, poll } from "../assets/api.js";

const api = new Api();
const banner = $("#banner");
const MAX_TIMELINE_ROWS = 40;

const state = { analysis: null, timeline: [] };

async function refresh() {
  try {
    const analysis = await api.analysis();
    state.analysis = analysis;
    showBanner(banner, "");
    $("#last-updated").textContent = `updated ${clockTime(new Date().toISOString())}`;

    renderScore();
    renderChain();
    renderDefense();
    renderTimeline();
  } catch (error) {
    showBanner(banner, humanize(error));
  }
}

function renderScore() {
  const a = state.analysis;
  $("#score-detected").textContent = `${a.detected} / ${a.red_actions}`;
  $("#score-rate").textContent = a.detection_rate === null ? "—" : `${(a.detection_rate * 100).toFixed(0)}%`;
}

/* ---------- 攻防進度 ---------- */

function renderChain() {
  const host = clear($("#chain"));
  const rows = state.analysis.correlations ?? [];
  if (rows.length === 0) {
    host.append(el("div", { class: "empty", text: "No attack activity registered yet." }));
    return;
  }

  let pending = 0;
  rows.forEach((row, i) => {
    const isPublicHit = row.status === "hit";
    if (!isPublicHit) pending += 1;
    host.append(el("span", {
      class: `dot ${isPublicHit ? "defended" : "pending"}`,
      text: isPublicHit ? `🟢 Attack #${i + 1} detected` : `○ Attack #${i + 1}`,
    }));
  });

  $("#disclosure-note").textContent = pending > 0
    ? `${pending} item(s) not yet shown as detected -- the specific outcome is decided by the purple team, not shown here first.`
    : "All observed attacks are shown as detected.";
}

/* ---------- 統計 ---------- */

function renderDefense() {
  const host = clear($("#defense"));
  const rows = [
    ["Red actions", String(state.analysis.red_actions)],
    ["Timeline events", String(state.timeline.length)],
  ];
  for (const [label, value] of rows) {
    host.append(el("div", { class: "stat-row" }, [
      el("span", { text: label }),
      el("span", { class: "val", text: value }),
    ]));
  }
}

/* ---------- 時間軸（只顯示公開的命中） ---------- */

function renderTimeline() {
  const rows = (state.analysis.correlations ?? [])
    .filter((r) => r.status === "hit")
    .slice(-MAX_TIMELINE_ROWS)
    .reverse();
  state.timeline = rows;

  const host = clear($("#timeline"));
  if (rows.length === 0) {
    host.append(el("div", { class: "empty", text: "No detections yet." }));
    return;
  }
  for (const row of rows) {
    host.append(el("div", { class: "timeline-row" }, [
      el("span", { class: "t", text: clockTime(row.blue?.observed_at) }),
      el("span", { text: "🟢 attack detected" }),
    ]));
  }
}

poll(5, refresh);
