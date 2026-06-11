const adminLoginForm = document.querySelector("#adminLoginForm");
const adminUsername = document.querySelector("#adminUsername");
const adminPassword = document.querySelector("#adminPassword");
const adminLoginStatus = document.querySelector("#adminLoginStatus");
const passwordToggles = document.querySelectorAll("[data-toggle-password]");
const toast = document.querySelector("#toast");

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 1600);
}

function setStatus(target, message, isError = false) {
  target.textContent = message;
  target.classList.toggle("error", isError);
}

async function checkAdminSession() {
  const response = await fetch("/api/admin/me");
  const result = await response.json();
  if (result.authenticated) {
    location.replace("/admin/dashboard");
  }
}

adminLoginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus(adminLoginStatus, "Signing in...");
  const data = new FormData();
  data.set("username", adminUsername.value.trim());
  data.set("password", adminPassword.value);
  const response = await fetch("/api/admin/login", { method: "POST", body: data });
  const result = await response.json();
  if (!response.ok) {
    setStatus(adminLoginStatus, result.error || "Could not sign in", true);
    return;
  }
  setStatus(adminLoginStatus, "");
  adminPassword.value = "";
  showToast("Signed in");
  location.replace("/admin/dashboard");
});

passwordToggles.forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.querySelector(button.dataset.togglePassword || "");
    if (!input) return;
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    button.textContent = show ? "Hide" : "Show";
    button.setAttribute("aria-label", show ? "Hide password" : "Show password");
  });
});

checkAdminSession();
