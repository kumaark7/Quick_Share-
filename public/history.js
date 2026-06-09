const historyList = document.querySelector("#historyList");
const historyCopy = document.querySelector("#historyCopy");
const historyAdminLink = document.querySelector("#historyAdminLink");
const historyAuthLink = document.querySelector("#historyAuthLink");
const historySignupLink = document.querySelector("#historySignupLink");
const historyRefreshBtn = document.querySelector("#historyRefreshBtn");
const toast = document.querySelector("#toast");

let currentUser = null;

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 1600);
}

function formatBytes(bytes = 0) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatExpiry(timestamp) {
  if (!timestamp) return "never expires";
  const seconds = Math.max(0, timestamp - Math.floor(Date.now() / 1000));
  if (seconds < 60) return "expires now";
  if (seconds < 3600) return `expires in ${Math.ceil(seconds / 60)}m`;
  if (seconds < 86400) return `expires in ${Math.ceil(seconds / 3600)}h`;
  return `expires in ${Math.ceil(seconds / 86400)}d`;
}

function formatOpenedAt(timestamp) {
  if (!timestamp) return "";
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - timestamp);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

async function copy(value, label) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      showToast(`${label} copied`);
      return true;
    }
  } catch (error) {
    console.warn("Clipboard write failed, falling back.", error);
  }

  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.appendChild(input);
  input.focus();
  input.select();

  try {
    const copied = document.execCommand("copy");
    showToast(copied ? `${label} copied` : `Copy ${label.toLowerCase()} manually`);
    return copied;
  } catch (error) {
    console.warn("Clipboard fallback failed.", error);
    showToast(`Copy ${label.toLowerCase()} manually`);
    return false;
  } finally {
    document.body.removeChild(input);
  }
}

function shareRow(share) {
  const row = document.createElement("article");
  row.className = "share-row";
  const title = share.kind === "file" ? share.filename : (share.text || "").slice(0, 60) || "Text share";
  const copyTextAction = share.kind === "text" && share.text
    ? "<button type=\"button\" data-copy-text>Copy text</button>"
    : "";
  const stats = share.view_stats || { total_opens: 0, qr_opens: 0, link_opens: 0, unique_devices: 0, top_devices: [], recent: [] };
  const topDevices = stats.top_devices.length
    ? stats.top_devices.map((item) => `${item.label} (${item.count})`).join(" · ")
    : "No opens yet";
  const recentOpens = stats.recent.length
    ? stats.recent.map((item) => `${item.device} on ${item.browser} via ${item.source === "qr" ? "QR" : "link"} · ${formatOpenedAt(item.opened_at)}`).join("<br>")
    : "No one has opened this share yet.";
  row.innerHTML = `
    <div class="share-main">
      <div class="share-title"></div>
      <div class="chips">
        <span>${share.kind}</span>
        <span>${formatBytes(share.size)}</span>
        <span>${formatExpiry(share.expires_at)}</span>
        ${share.password_protected ? "<span>locked</span>" : ""}
      </div>
      <div class="share-stats">
        <strong>${stats.total_opens}</strong> opens ·
        <strong>${stats.unique_devices}</strong> devices ·
        <strong>${stats.qr_opens}</strong> by QR ·
        <strong>${stats.link_opens}</strong> by link
      </div>
      <div class="share-meta-note">${topDevices}</div>
      <div class="share-meta-note">${recentOpens}</div>
    </div>
    <div class="row-actions">
      <a href="${share.url}" target="_blank" rel="noreferrer">Open</a>
      <button type="button" data-copy-link>Copy link</button>
      <button type="button" data-share-again>Share again</button>
      ${share.kind === "file" ? "<a data-open-file>Download</a>" : copyTextAction}
      <button type="button" data-delete>Delete</button>
    </div>
  `;
  row.querySelector(".share-title").textContent = title;
  row.querySelector("[data-copy-link]").addEventListener("click", () => copy(share.url, "Link"));
  const copyTextButton = row.querySelector("[data-copy-text]");
  if (copyTextButton) copyTextButton.addEventListener("click", () => copy(share.text, "Text"));
  const fileLink = row.querySelector("[data-open-file]");
  if (fileLink) fileLink.href = share.download_url;
  row.querySelector("[data-share-again]").addEventListener("click", async () => {
    const response = await fetch(`/api/share-again/${share.id}`, { method: "POST" });
    const result = await response.json();
    if (!response.ok) {
      showToast(result.error || "Could not create new share");
      return;
    }
    const newShare = result.share;
    await copy(newShare.url, "Link");
    showToast("New share created and copied");
    loadHistory();
  });
  row.querySelector("[data-delete]").addEventListener("click", async () => {
    const response = await fetch(`/api/share/${share.id}`, { method: "DELETE" });
    const result = await response.json();
    if (!response.ok) {
      showToast(result.error || "Could not delete share");
      return;
    }
    showToast("Share deleted");
    loadHistory();
  });
  return row;
}

async function loadMe() {
  const response = await fetch("/api/me");
  const result = await response.json();
  currentUser = result.authenticated ? result.user : null;
  historyAdminLink.classList.toggle("hidden", !(currentUser && currentUser.is_admin));
  historyAuthLink.textContent = currentUser ? `Signed in: ${currentUser.username}` : "Sign In";
  historySignupLink.classList.toggle("hidden", Boolean(currentUser));
  historyCopy.textContent = currentUser
    ? `Saved shares for ${currentUser.username}. Open, copy, or delete anything you stored.`
    : "Sign in to view saved text snippets and files from your account.";
}

async function loadHistory() {
  const response = await fetch("/api/profile/shares");
  if (response.status === 401) {
    historyList.innerHTML = `<div class="empty">Sign in first on the account page, then your saved history will appear here.</div>`;
    return;
  }
  const shares = await response.json();
  historyList.innerHTML = "";
  if (!shares.length) {
    historyList.innerHTML = `<div class="empty">No saved shares yet. Create one from the home page with save to history turned on.</div>`;
    return;
  }
  shares.forEach((share) => historyList.appendChild(shareRow(share)));
}

historyRefreshBtn.addEventListener("click", loadHistory);

loadMe().then(loadHistory);
