const form = document.querySelector("#shareForm");
const tabs = document.querySelectorAll("[data-kind]");
const textPanel = document.querySelector("#textPanel");
const filePanel = document.querySelector("#filePanel");
const textInput = document.querySelector("#textInput");
const fileInput = document.querySelector("#fileInput");
const fileName = document.querySelector("#fileName");
const expiresInput = document.querySelector("#expiresInput");
const passwordInput = document.querySelector("#passwordInput");
const saveRow = document.querySelector("#saveRow");
const saveToProfileInput = document.querySelector("#saveToProfileInput");
const statusLine = document.querySelector("#status");
const toast = document.querySelector("#toast");
const refreshBtn = document.querySelector("#refreshBtn");
const addressBar = document.querySelector("#addressBar");
const authLink = document.querySelector("#authLink");
const signupLink = document.querySelector("#signupLink");
const adminLink = document.querySelector("#adminLink");
const resultCard = document.querySelector("#resultCard");
const resultLink = document.querySelector("#resultLink");
const copyResultBtn = document.querySelector("#copyResultBtn");
const qrImage = document.querySelector("#qrImage");
const NEVER_OPTION = '<option value="never">Never</option>';

let activeKind = "text";
let currentUser = null;

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 1600);
}

function setStatus(message, isError = false) {
  statusLine.textContent = message;
  statusLine.classList.toggle("error", isError);
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

function renderResult(url) {
  resultCard.classList.remove("hidden");
  resultLink.href = url;
  resultLink.textContent = url;
  qrImage.src = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(`${url}?src=qr`)}`;
  qrImage.loading = "lazy";
}

async function loadMe() {
  const response = await fetch("/api/me");
  const result = await response.json();
  currentUser = result.authenticated ? result.user : null;
  saveRow.classList.toggle("hidden", !currentUser);
  saveToProfileInput.disabled = !currentUser;
  authLink.textContent = currentUser ? `Signed in: ${currentUser.username}` : "Sign In";
  signupLink.classList.toggle("hidden", Boolean(currentUser));
  adminLink.classList.toggle("hidden", !(currentUser && currentUser.is_admin));
  const hasNever = expiresInput.querySelector('option[value="never"]');
  if (currentUser && !hasNever) {
    expiresInput.insertAdjacentHTML("beforeend", NEVER_OPTION);
  }
  if (!currentUser && hasNever) {
    if (expiresInput.value === "never") expiresInput.value = "48";
    hasNever.remove();
  }
}

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    activeKind = tab.dataset.kind;
    tabs.forEach((item) => item.classList.toggle("active", item === tab));
    textPanel.classList.toggle("hidden", activeKind !== "text");
    filePanel.classList.toggle("hidden", activeKind !== "file");
    setStatus("");
  });
});

fileInput.addEventListener("change", () => {
  fileName.textContent = fileInput.files[0] ? fileInput.files[0].name : "or drag it here from your desktop";
});

["dragenter", "dragover"].forEach((eventName) => {
  filePanel.addEventListener(eventName, (event) => {
    event.preventDefault();
    filePanel.classList.add("dragging");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  filePanel.addEventListener(eventName, (event) => {
    event.preventDefault();
    filePanel.classList.remove("dragging");
  });
});

filePanel.addEventListener("drop", (event) => {
  const [file] = event.dataTransfer.files;
  if (!file) return;
  fileInput.files = event.dataTransfer.files;
  fileName.textContent = file.name;
});

async function loadMeta() {
  const response = await fetch("/api/meta");
  const meta = await response.json();
  const host = window.location.hostname;
  const protocol = window.location.protocol;
  const isLocalHost = ["localhost", "127.0.0.1"].includes(host);
  const isPrivateIp = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(host);

  addressBar.innerHTML = "";

  if (!isLocalHost && !isPrivateIp) {
    addressBar.classList.remove("hidden");
    addressBar.innerHTML = `<span>Open on another device: ${window.location.origin}</span>`;
    return;
  }

  const lan = meta.addresses.filter((address) => address !== "127.0.0.1");
  if (!lan.length) return;

  addressBar.classList.remove("hidden");
  addressBar.innerHTML = lan
    .map((address) => `<span>Open on another device: ${protocol}//${address}${window.location.port ? `:${window.location.port}` : ""}</span>`)
    .join("");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData();
  data.set("kind", activeKind);
  data.set("expires", expiresInput.value);
  data.set("password", passwordInput.value);
  data.set("save_to_profile", currentUser && saveToProfileInput.checked ? "true" : "false");
  if (activeKind === "text") {
    data.set("text", textInput.value);
  } else if (fileInput.files[0]) {
    data.set("file", fileInput.files[0]);
  }

  setStatus("Creating share...");
  const response = await fetch("/api/share", { method: "POST", body: data });
  const result = await response.json();
  if (!response.ok) {
    setStatus(result.error || "Could not create share", true);
    return;
  }

  renderResult(result.url);
  setStatus(`Ready: ${result.url}`);
  await copy(result.url, "Share link");
  if (activeKind === "text") textInput.value = "";
  passwordInput.value = "";
  saveToProfileInput.checked = true;
  if (activeKind === "file") {
    fileInput.value = "";
    fileName.textContent = "or drag it here from your desktop";
  }
});

refreshBtn.addEventListener("click", () => window.location.reload());
copyResultBtn.addEventListener("click", () => copy(resultLink.href, "Link"));

loadMeta();
loadMe();
