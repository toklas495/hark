// hark — capture service worker.
//
// How it captures: it attaches Chrome's own DevTools debugger (CDP) to each
// tab and listens to Network.* events — the exact same traffic the Network
// panel shows. It does NOT act as a proxy. Nothing is rewritten or delayed;
// we watch requests go by and POST a copy to the local hark listener. That's
// the whole point: "watch, don't sit in the middle" — so a corporate proxy /
// EDR that chokes on Burp never sees anything unusual.

// ---- state ----
let captureEnabled = false;
let scopeRules = [];
let listenerUrl = "http://127.0.0.1:8787/capture";
let token = ""; // X-Hark-Token — must match the listener's -token
const attached = new Set();
const declinedTabs = new Set();
const pendingRequests = new Map();
const pendingReqExtra = new Map();
const pendingResExtra = new Map();
let ready = loadSettings();

const RESTRICTED = /^(chrome|edge|about|chrome-extension|chrome-untrusted):|^https:\/\/chrome\.google\.com\/webstore/;
const MAX_BODY_CHARS = 200_000;

function key(tabId, requestId) { return `${tabId}:${requestId}`; }

function setBadge(tabId, state) {
  const s = {
    on:       { text: "●", color: "#22c55e", title: "hark — capturing this tab" },
    declined: { text: "●", color: "#ef4444", title: "hark — declined here. Toggle capture off/on to retry." },
    off:      { text: "",  color: "#9ca3af", title: "hark — disabled" },
  }[state] || { text: "", color: "#9ca3af", title: "hark" };
  chrome.action.setBadgeText({ tabId, text: s.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: s.color });
  chrome.action.setTitle({ tabId, title: s.title });
}

function loadSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["captureEnabled", "scopeRules", "listenerUrl", "token"], (r) => {
      captureEnabled = !!r.captureEnabled;
      scopeRules = r.scopeRules || [];
      listenerUrl = r.listenerUrl || listenerUrl;
      token = r.token || "";
      resolve();
    });
  });
}

chrome.runtime.onInstalled.addListener(() => { ready = loadSettings(); });
chrome.runtime.onStartup.addListener(() => { ready = loadSettings(); });

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") return;
  if (changes.captureEnabled) captureEnabled = changes.captureEnabled.newValue;
  if (changes.scopeRules) scopeRules = changes.scopeRules.newValue || [];
  if (changes.listenerUrl) listenerUrl = changes.listenerUrl.newValue;
  if (changes.token) token = changes.token.newValue || "";
  if (changes.captureEnabled) {
    if (!captureEnabled) {
      detachAll();
    } else {
      declinedTabs.clear();
      reattachAllOpenTabs();
    }
  }
});

function attachable(url) {
  return !!url && !RESTRICTED.test(url);
}

// Scope is matched against the REQUEST's own host (e.g. api.example.com),
// not the tab's page host (e.g. app.example.com) — a page and the API it
// calls are very often different domains.
function requestInScope(url) {
  if (!scopeRules.length) return true;
  try {
    const h = new URL(url).hostname;
    return scopeRules.some((rule) => h === rule || h.endsWith("." + rule));
  } catch { return false; }
}

async function attachTab(tabId, url) {
  if (!captureEnabled || attached.has(tabId) || declinedTabs.has(tabId) || !attachable(url)) {
    if (!attached.has(tabId) && !declinedTabs.has(tabId)) setBadge(tabId, "off");
    return;
  }
  try {
    await chrome.debugger.attach({ tabId }, "1.3");
    await chrome.debugger.sendCommand({ tabId }, "Network.enable");
    attached.add(tabId);
    setBadge(tabId, "on");
  } catch (err) {
    console.warn("[hark] attach failed for tab", tabId, "-", err.message);
  }
}

async function detachTab(tabId) {
  if (!attached.has(tabId)) return;
  try { await chrome.debugger.detach({ tabId }); } catch {}
  attached.delete(tabId);
  setBadge(tabId, "off");
}

async function detachAll() {
  for (const id of [...attached]) await detachTab(id);
}

async function reattachAllOpenTabs() {
  const tabs = await chrome.tabs.query({});
  for (const t of tabs) if (t.id && t.url) await attachTab(t.id, t.url);
}

chrome.debugger.onDetach.addListener((source, reason) => {
  if (!source.tabId) return;
  attached.delete(source.tabId);
  if (reason === "canceled_by_user") {
    declinedTabs.add(source.tabId);
    setBadge(source.tabId, "declined");
  }
});

chrome.tabs.onCreated.addListener(async (tab) => {
  await ready;
  if (tab.id && tab.url) attachTab(tab.id, tab.url);
});
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  await ready;
  if (info.status === "loading" && tab.url) attachTab(tabId, tab.url);
});
chrome.tabs.onRemoved.addListener((tabId) => {
  attached.delete(tabId);
  declinedTabs.delete(tabId);
  for (const [k, e] of pendingRequests) if (e.tabId === tabId) pendingRequests.delete(k);
  for (const k of pendingReqExtra.keys()) if (k.startsWith(tabId + ":")) pendingReqExtra.delete(k);
  for (const k of pendingResExtra.keys()) if (k.startsWith(tabId + ":")) pendingResExtra.delete(k);
});

chrome.debugger.onEvent.addListener((source, method, params) => {
  const tabId = source.tabId;

  if (method === "Network.requestWillBeSent") {
    const { requestId, request, type, redirectResponse } = params;
    const k = key(tabId, requestId);

    if (redirectResponse && pendingRequests.has(k)) {
      const prior = pendingRequests.get(k);
      prior.status = redirectResponse.status;
      prior.statusText = redirectResponse.statusText || "";
      prior.responseHeaders = redirectResponse.headers;
      finalizeAndSend(prior);
      pendingRequests.delete(k);
    }

    if (!requestInScope(request.url)) return;

    const entry = {
      requestId, tabId, resourceType: type,
      method: request.method, url: request.url,
      requestHeaders: request.headers,
      requestBody: request.postData || "",
      status: 0, statusText: "", responseHeaders: null, mimeType: "",
      responseBody: "", responseBodyEncoding: "",
    };
    pendingRequests.set(k, entry);

    const rex = pendingReqExtra.get(k);
    if (rex) {
      entry.requestHeaders = { ...entry.requestHeaders, ...rex.headers };
      pendingReqExtra.delete(k);
    }

    if (request.hasPostData && !request.postData) {
      chrome.debugger.sendCommand({ tabId }, "Network.getRequestPostData", { requestId })
        .then((r) => { entry.requestBody = r.postData; })
        .catch(() => {});
    }
  } else if (method === "Network.requestWillBeSentExtraInfo") {
    const k = key(tabId, params.requestId);
    const e = pendingRequests.get(k);
    if (e) {
      e.requestHeaders = { ...e.requestHeaders, ...params.headers };
    } else {
      pendingReqExtra.set(k, { headers: params.headers });
    }
  } else if (method === "Network.responseReceivedExtraInfo") {
    const k = key(tabId, params.requestId);
    const e = pendingRequests.get(k);
    if (e) {
      e.responseHeaders = { ...e.responseHeaders, ...params.headers };
    } else {
      pendingResExtra.set(k, { headers: params.headers });
    }
  } else if (method === "Network.responseReceived") {
    const e = pendingRequests.get(key(tabId, params.requestId));
    if (e) {
      e.status = params.response.status;
      e.statusText = params.response.statusText || "";
      e.responseHeaders = params.response.headers;
      e.mimeType = params.response.mimeType;
      const rex = pendingResExtra.get(key(tabId, params.requestId));
      if (rex) {
        e.responseHeaders = { ...e.responseHeaders, ...rex.headers };
        pendingResExtra.delete(key(tabId, params.requestId));
      }
    }
  } else if (method === "Network.loadingFinished") {
    finishAndFlush(tabId, params.requestId);
    pendingReqExtra.delete(key(tabId, params.requestId));
    pendingResExtra.delete(key(tabId, params.requestId));
  } else if (method === "Network.loadingFailed") {
    const k = key(tabId, params.requestId);
    pendingRequests.delete(k);
    pendingReqExtra.delete(k);
    pendingResExtra.delete(k);
  }
});

async function finishAndFlush(tabId, requestId) {
  const k = key(tabId, requestId);
  const e = pendingRequests.get(k);
  pendingRequests.delete(k);
  if (!e || !e.url) return;
  try {
    const body = await chrome.debugger.sendCommand({ tabId }, "Network.getResponseBody", { requestId });
    let text = body.body || "";
    if (text.length > MAX_BODY_CHARS) text = text.slice(0, MAX_BODY_CHARS) + "…[truncated]";
    e.responseBody = text;
    e.responseBodyEncoding = body.base64Encoded ? "base64" : "";
  } catch {
    // body not retrievable (opaque response, evicted, tab closed) — send without it
  }
  finalizeAndSend(e);
}

async function finalizeAndSend(e) {
  const { requestId: _drop, ...payload } = e;
  payload.timestamp = Date.now();
  const headers = { "Content-Type": "application/json" };
  if (token) headers["X-Hark-Token"] = token;
  try {
    const res = await fetch(listenerUrl, { method: "POST", headers, body: JSON.stringify(payload) });
    if (res.status === 401) {
      console.error("[hark] listener rejected: bad/missing token. Paste the listener's token into the popup.");
    } else if (!res.ok) {
      console.error("[hark] listener rejected entry:", res.status, await res.text().catch(() => ""));
    }
  } catch (err) {
    console.error("[hark] listener unreachable:", err.message, "→", listenerUrl, "— is `hark listen` running?");
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    await ready;
    if (msg.type === "GET_STATUS") {
      sendResponse({ captureEnabled, scopeRules, listenerUrl, token, declinedCount: declinedTabs.size });
    } else if (msg.type === "SET_ENABLED") {
      captureEnabled = msg.value;
      await chrome.storage.local.set({ captureEnabled });
      sendResponse({ ok: true });
    } else if (msg.type === "ADD_RULE") {
      scopeRules = [...new Set([...scopeRules, msg.rule])];
      await chrome.storage.local.set({ scopeRules });
      sendResponse({ ok: true, scopeRules });
    } else if (msg.type === "REMOVE_RULE") {
      scopeRules = scopeRules.filter((r) => r !== msg.rule);
      await chrome.storage.local.set({ scopeRules });
      sendResponse({ ok: true, scopeRules });
    } else if (msg.type === "SET_LISTENER_URL") {
      listenerUrl = msg.value;
      await chrome.storage.local.set({ listenerUrl });
      sendResponse({ ok: true });
    } else if (msg.type === "SET_TOKEN") {
      token = msg.value;
      await chrome.storage.local.set({ token });
      sendResponse({ ok: true });
    }
  })();
  return true;
});
