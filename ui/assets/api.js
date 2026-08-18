/* 前端共用小工具 + 一層薄薄的 fetch 包裝。
 *
 * 搬自 cyber 的 ui/assets/api.js（issue #3），拿掉了 `/gw/<identity>`
 * 服務身分閘道，換成單一共用 bearer token（跟 /ingest/* 同一把）。請求直接
 * 打這個 repo 自己的端點（見 docs/INTERFACE_CONTRACT.md）；`caller` 仍是
 * 一個普通的 query 參數，但 `caller=purple` 現在會帶上 token，後端才擋得住
 * 「網址上把 caller 改成 purple 就能繞過分級」這種事。
 */

export class ApiError extends Error {
  constructor(status, detail, { path } = {}) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.path = path;
  }
}

/** 把後端錯誤翻成畫面上敢直接顯示的一句話。 */
export function humanize(error) {
  if (!(error instanceof ApiError)) return "Connection failed -- is the collector running?";
  switch (error.status) {
    case 404: return error.detail || "No matching data (maybe nothing ingested yet).";
    case 422: return error.detail || "Invalid request.";
    default: return `Backend returned ${error.status}.`;
  }
}

/* `caller=purple` 現在後端要驗 bearer token（跟 /ingest/* 同一把共用密鑰，
 * 見 docs/INTERFACE_CONTRACT.md #authentication）——不然任何人把網址上的
 * caller 改成 purple 就能繞過整套 disclosure 分級。這個 console 本來就沒
 * 有登入頁，這裡用「第一次要 purple 資料時跳 prompt 問一次、存
 * sessionStorage」這個最小手法頂著，密碼錯了（401）就清掉重問一次。 */
const TOKEN_KEY = "rbcollector_purple_token";

function getPurpleToken() {
  let token = sessionStorage.getItem(TOKEN_KEY);
  if (!token) {
    token = window.prompt("Purple clearance token (shared ingest token):") ?? "";
    sessionStorage.setItem(TOKEN_KEY, token);
  }
  return token;
}

async function request(path, { purple = false } = {}) {
  let response;
  try {
    const headers = purple ? { Authorization: `Bearer ${getPurpleToken()}` } : undefined;
    response = await fetch(path, headers ? { headers } : undefined);
  } catch (cause) {
    console.error("network failure", path, cause);
    throw new ApiError(0, "network failure", { path });
  }

  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { detail: text };
    }
  }

  if (!response.ok) {
    if (purple && response.status === 401) sessionStorage.removeItem(TOKEN_KEY);
    const detail = typeof payload?.detail === "string" ? payload.detail : JSON.stringify(payload ?? "");
    console.error("api error", response.status, path, detail);
    throw new ApiError(response.status, detail, { path });
  }
  return payload;
}

/** 這個 UI 會打的所有端點。每個頁面一個實例就夠。 */
export class Api {
  timeline(limit = 500) { return request(`/timeline?limit=${limit}`); }
  /** `caller`：`"public"`（預設，安全視角）或 `"purple"`（需要 token，見上）。 */
  analysis(limit = 5000, caller = "public") {
    return request(`/analysis?limit=${limit}&caller=${caller}`, { purple: caller === "purple" });
  }
  /** `caller`：`"public"` 或 `"purple"`——見 docs/INTERFACE_CONTRACT.md。 */
  context(eventId, caller, windowMinutes = 5) {
    return request(`/events/${encodeURIComponent(eventId)}/context?caller=${caller}&window_minutes=${windowMinutes}`, { purple: caller === "purple" });
  }
}

/* ---------- 各畫面共用的小型 DOM 工具（不含商業邏輯） ---------- */

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

/** 一律用 textContent 建節點，不拼 innerHTML——事件內容含攻擊者可控字串
 *  （message、source_ip），拼字串進 innerHTML 就是 stored XSS 的成因。 */
export function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2).toLowerCase(), value);
    else node.setAttribute(key, value);
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export function renderEmpty(node, reason) {
  clear(node).append(el("div", { class: "empty", text: reason }));
}

export function showBanner(node, message, kind = "error") {
  node.className = `banner ${kind}`;
  node.textContent = message ?? "";
}

export const clockTime = (iso) => {
  if (!iso) return "—";
  const at = new Date(iso);
  return Number.isNaN(at.getTime()) ? "—" : at.toLocaleTimeString("en-GB", { hour12: false });
};

/** 每 `seconds` 秒跑一次 `task`，並且立刻先跑一次。回傳停止函式。 */
export function poll(seconds, task) {
  let stopped = false;
  const tick = async () => {
    if (stopped) return;
    try {
      await task();
    } catch (cause) {
      console.error("poll task failed", cause);
    }
  };
  tick();
  const handle = setInterval(tick, seconds * 1000);
  return () => { stopped = true; clearInterval(handle); };
}
