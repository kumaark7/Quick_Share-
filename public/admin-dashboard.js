const adminSearch = document.querySelector("#adminSearch");
const adminRefreshBtn = document.querySelector("#adminRefreshBtn");
const adminExportBtn = document.querySelector("#adminExportBtn");
const adminLogoutBtn = document.querySelector("#adminLogoutBtn");
const adminStatus = document.querySelector("#adminStatus");
const adminTableBody = document.querySelector("#adminTableBody");
const toast = document.querySelector("#toast");
const adminContextMenu = document.querySelector("#adminContextMenu");

let allUsers = [];
let openMenuUser = null;
let openMenuStatus = "";

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 1600);
}

function setStatus(message, isError = false) {
  adminStatus.textContent = message;
  adminStatus.classList.toggle("error", isError);
}

function formatDate(timestamp) {
  if (!timestamp) return "-";
  return new Date(timestamp * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatLastActive(timestamp) {
  if (!timestamp) return "-";
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - timestamp);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 2592000) return `${Math.floor(seconds / 86400)}d ago`;
  return formatDate(timestamp);
}

function formatBytes(bytes = 0) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function downloadFile(name, content) {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function filteredUsers() {
  const query = adminSearch.value.trim().toLowerCase();
  if (!query) return allUsers;
  return allUsers.filter((user) =>
    user.email.toLowerCase().includes(query) || user.username.toLowerCase().includes(query)
  );
}

async function deleteUser(userId) {
  const response = await fetch(`/api/admin/users/${userId}`, { method: "DELETE" });
  const result = await response.json();
  if (!response.ok) {
    showToast(result.error || "Could not delete user");
    return;
  }
  showToast("User deleted");
  loadUsers();
}

async function updateUserStatus(userId, status) {
  const data = new FormData();
  data.set("status", status);
  const response = await fetch(`/api/admin/users/${userId}/status`, { method: "POST", body: data });
  const result = await response.json();
  if (!response.ok) {
    showToast(result.error || "Could not update account");
    return;
  }
  showToast(result.message || `Account set to ${result.status}`);
  loadUsers();
}

function renderUsers() {
  const users = filteredUsers();
  adminTableBody.innerHTML = "";

  if (!users.length) {
    adminTableBody.innerHTML = `<tr><td colspan="9" class="admin-empty">No users match this search.</td></tr>`;
    return;
  }

  users.forEach((user) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>
        <div class="admin-primary">${user.email}</div>
        <div class="admin-secondary">@${user.username}</div>
      </td>
      <td>
        <span class="admin-pill ${user.status.toLowerCase()}">${user.status}</span>
        <div class="admin-secondary">${user.role}</div>
      </td>
      <td>
        <div class="admin-secondary">Joined ${formatDate(user.joined_at)}</div>
        <div class="admin-secondary">Active ${formatLastActive(user.last_active_at)}</div>
      </td>
      <td>${formatBytes(user.storage_used)}</td>
      <td>${user.share_count}</td>
      <td>
        <div class="admin-actions">
          <button class="ghost" type="button" data-copy-email>Copy Email</button>
          <button class="ghost admin-menu-toggle" type="button" data-menu-toggle aria-label="Open actions menu" aria-expanded="false">...</button>
        </div>
      </td>
    `;
    const menuToggle = row.querySelector("[data-menu-toggle]");
    row.querySelector("[data-copy-email]").addEventListener("click", async () => {
      await navigator.clipboard.writeText(user.email).catch(() => {});
      showToast("Email copied");
    });
    menuToggle.addEventListener("click", (event) => {
      event.stopPropagation();
      toggleContextMenu(menuToggle, user);
    });
    adminTableBody.appendChild(row);
  });
}

function closeContextMenu() {
  adminContextMenu.classList.add("hidden");
  openMenuUser = null;
  openMenuStatus = "";
  document.querySelectorAll(".admin-menu-toggle").forEach((button) => button.setAttribute("aria-expanded", "false"));
}

function positionContextMenu(toggle) {
  const rect = toggle.getBoundingClientRect();
  const menuWidth = 190;
  const left = Math.max(12, Math.min(rect.right - menuWidth, window.innerWidth - menuWidth - 12));
  const top = Math.min(rect.bottom + 10, window.innerHeight - 220);
  adminContextMenu.style.left = `${left}px`;
  adminContextMenu.style.top = `${Math.max(12, top)}px`;
}

function toggleContextMenu(toggle, user) {
  const sameUser = openMenuUser && openMenuUser.id === user.id && !adminContextMenu.classList.contains("hidden");
  closeContextMenu();
  if (sameUser) return;
  openMenuUser = user;
  openMenuStatus = user.status;
  positionContextMenu(toggle);
  adminContextMenu.classList.remove("hidden");
  toggle.setAttribute("aria-expanded", "true");
  const activate = adminContextMenu.querySelector('[data-menu-action="activate"]');
  const suspend = adminContextMenu.querySelector('[data-menu-action="suspend"]');
  const ban = adminContextMenu.querySelector('[data-menu-action="ban"]');
  activate.disabled = user.status === "Pending" || user.status === "Active";
  suspend.disabled = user.status === "Pending" || user.status === "Suspended";
  ban.disabled = user.status === "Pending" || user.status === "Banned";
}

adminContextMenu.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof Element)) return;
  const action = target.getAttribute("data-menu-action");
  if (!action || !openMenuUser) return;
  const userId = openMenuUser.id;
  closeContextMenu();
  if (action === "delete") {
    deleteUser(userId);
    return;
  }
  updateUserStatus(userId, action);
});

document.addEventListener("click", () => {
  closeContextMenu();
});

window.addEventListener("resize", closeContextMenu);
window.addEventListener("scroll", closeContextMenu, true);

function exportUsers() {
  const rows = filteredUsers();
  const lines = [
    ["Email", "Username", "Status", "Role", "Joined", "Last Active", "Storage Used (bytes)", "Share Count"].join(","),
    ...rows.map((user) => [
      user.email,
      user.username,
      user.status,
      user.role,
      formatDate(user.joined_at),
      formatLastActive(user.last_active_at),
      user.storage_used,
      user.share_count,
    ].map((value) => `"${String(value).replaceAll('"', '""')}"`).join(",")),
  ];
  downloadFile("quick-share-users.csv", lines.join("\n"));
  showToast("User list exported");
}

async function loadUsers() {
  setStatus("Loading users...");
  const response = await fetch("/api/admin/users");
  const result = await response.json();
  if (response.status === 403) {
    location.replace("/admin");
    return;
  }
  if (!response.ok) {
    adminTableBody.innerHTML = "";
    setStatus(result.error || "Could not load users", true);
    return;
  }
  allUsers = result;
  setStatus(`Loaded ${allUsers.length} users.`);
  renderUsers();
}

async function checkAdminSession() {
  const response = await fetch("/api/admin/me");
  const result = await response.json();
  if (!result.authenticated) {
    location.replace("/admin");
    return;
  }
  loadUsers();
}

adminSearch.addEventListener("input", renderUsers);
adminRefreshBtn.addEventListener("click", loadUsers);
adminExportBtn.addEventListener("click", exportUsers);
adminLogoutBtn.addEventListener("click", async () => {
  await fetch("/api/admin/logout", { method: "POST" });
  location.replace("/admin");
});

checkAdminSession();
