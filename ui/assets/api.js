/* 前端共用小工具 + 一層薄薄的 fetch 包裝。
 *
 * 搬自 cyber 的 ui/assets/api.js（issue #3），拿掉了 `/gw/<identity>`
 * 服務身分閘道——rbcollector 沒有身分驗證這層。請求直接打這個 repo 自己的
 * 端點（見 docs/INTERFACE_CONTRACT.md）；/events/{id}/context 的 `caller`
 * 在這裡只是一個普通的 query 參數，不是後端注入的身分。
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

async function request(path) {
  let response;
  try {
    response = await fetch(path);
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
    const detail = typeof payload?.detail === "string" ? payload.detail : JSON.stringify(payload ?? "");
    console.error("api error", response.status, path, detail);
    throw new ApiError(response.status, detail, { path });
  }
  return payload;
}

/** 這個 UI 會打的所有端點。每個頁面一個實例就夠。 */
export class Api {
  timeline(limit = 500) { return request(`/timeline?limit=${limit}`); }
  analysis(limit = 5000) { return request(`/analysis?limit=${limit}`); }
  /** `caller`：`"public"` 或 `"purple"`——見 docs/INTERFACE_CONTRACT.md。 */
  context(eventId, caller, windowMinutes = 5) {
    return request(`/events/${encodeURIComponent(eventId)}/context?caller=${caller}&window_minutes=${windowMinutes}`);
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
