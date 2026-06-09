const adminSearch = document.querySelector("#adminSearch");
const adminRefreshBtn = document.querySelector("#adminRefreshBtn");
const adminExportBtn = document.querySelector("#adminExportBtn");
const adminStatus = document.querySelector("#adminStatus");
const adminTableBody = document.querySelector("#adminTableBody");
const toast = document.querySelector("#toast");

let allUsers = [];

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

function renderUsers() {
  const users = filteredUsers();
  adminTableBody.innerHTML = "";

  if (!users.length) {
    adminTableBody.innerHTML = `<tr><td colspan="9" class="admin-empty">No users match this search.</td></tr>`;
    return;
  }

  users.forEach((user) => {
    const row = document.createElement("tr");
    const isAdmin = user.role === "Admin";
    row.innerHTML = `
      <td>${user.email}</td>
      <td>${user.username}</td>
      <td><span class="admin-pill ${user.status.toLowerCase()}">${user.status}</span></td>
      <td>${user.role}</td>
      <td>${formatDate(user.joined_at)}</td>
      <td>${formatLastActive(user.last_active_at)}</td>
      <td>${formatBytes(user.storage_used)}</td>
      <td>${user.share_count}</td>
      <td>
        <div class="admin-actions">
          <button class="ghost" type="button" data-copy-email>Copy Email</button>
          <button class="ghost danger" type="button" data-delete ${isAdmin ? "disabled" : ""}>Delete</button>
        </div>
      </td>
    `;
    row.querySelector("[data-copy-email]").addEventListener("click", async () => {
      await navigator.clipboard.writeText(user.email).catch(() => {});
      showToast("Email copied");
    });
    row.querySelector("[data-delete]").addEventListener("click", () => {
      if (isAdmin) return;
      deleteUser(user.id);
    });
    adminTableBody.appendChild(row);
  });
}

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
  if (!response.ok) {
    adminTableBody.innerHTML = "";
    setStatus(result.error || "Could not load users", true);
    return;
  }
  allUsers = result;
  setStatus(`Loaded ${allUsers.length} users.`);
  renderUsers();
}

adminSearch.addEventListener("input", renderUsers);
adminRefreshBtn.addEventListener("click", loadUsers);
adminExportBtn.addEventListener("click", exportUsers);

loadUsers();
