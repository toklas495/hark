const $ = (id) => document.getElementById(id);

function send(msg, cb) {
  chrome.runtime.sendMessage(msg, (res) => {
    if (chrome.runtime.lastError) {
      console.warn("[hark popup]", chrome.runtime.lastError.message);
      return;
    }
    cb && cb(res);
  });
}

function renderRules(rules) {
  $("rules").innerHTML = "";
  rules.forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    const btn = document.createElement("button");
    btn.textContent = "×";
    btn.onclick = () => send({ type: "REMOVE_RULE", rule: r }, (res) => renderRules(res.scopeRules));
    li.appendChild(btn);
    $("rules").appendChild(li);
  });
}

// Live connection check: hit the listener's /health (sibling of /capture).
// Shows a green/red dot so you know the listener is up before you start.
async function checkConn(listenerUrl) {
  let healthUrl;
  try { healthUrl = new URL(listenerUrl).origin + "/health"; }
  catch { healthUrl = "http://127.0.0.1:8787/health"; }
  try {
    const r = await fetch(healthUrl, { cache: "no-store" });
    const j = await r.json();
    $("dot").className = "ok";
    $("conn").textContent = `${j.entries ?? 0} captured`;
  } catch {
    $("dot").className = "bad";
    $("conn").textContent = "listener down";
  }
}

send({ type: "GET_STATUS" }, (status) => {
  $("enabled").checked = status.captureEnabled;
  $("listenerUrl").value = status.listenerUrl;
  $("token").value = status.token || "";
  renderRules(status.scopeRules);
  checkConn(status.listenerUrl);
  if (status.declinedCount > 0) {
    $("status").style.display = "block";
    $("status").textContent = `${status.declinedCount} tab(s) declined debugging — toggle capture off/on to retry.`;
  }
});

$("enabled").onchange = (e) => send({ type: "SET_ENABLED", value: e.target.checked });

$("addRule").onclick = () => {
  const v = $("ruleInput").value.trim();
  if (!v) return;
  send({ type: "ADD_RULE", rule: v }, (res) => { renderRules(res.scopeRules); $("ruleInput").value = ""; });
};

$("saveUrl").onclick = () => {
  const v = $("listenerUrl").value.trim();
  if (!v) return;
  send({ type: "SET_LISTENER_URL", value: v }, () => checkConn(v));
};

$("saveToken").onclick = () => {
  const v = $("token").value.trim();
  send({ type: "SET_TOKEN", value: v }, () => { $("saveToken").textContent = "✓"; setTimeout(() => ($("saveToken").textContent = "Save"), 900); });
};
