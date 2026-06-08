const authTabs = document.querySelectorAll("[data-auth-mode]");
const authTitle = document.querySelector("#authTitle");
const authSubtitle = document.querySelector("#authSubtitle");
const authForm = document.querySelector("#authForm");
const authUsername = document.querySelector("#authUsername");
const authPassword = document.querySelector("#authPassword");
const authSubmit = document.querySelector("#authSubmit");
const authStatus = document.querySelector("#authStatus");
const logoutBtn = document.querySelector("#logoutBtn");

let authMode = "login";
let currentUser = null;

function setAuthStatus(message, isError = false) {
  authStatus.textContent = message;
  authStatus.classList.toggle("error", isError);
}

function updateAuthUI() {
  const signedIn = Boolean(currentUser);
  authTabs.forEach((tab) => tab.classList.toggle("hidden", signedIn));
  authUsername.disabled = signedIn;
  authPassword.disabled = signedIn;
  authSubmit.classList.toggle("hidden", signedIn);
  logoutBtn.classList.toggle("hidden", !signedIn);

  if (signedIn) {
    authTitle.textContent = `Signed in as ${currentUser.username}`;
    authSubtitle.textContent = "Your account is ready. Open My History to see saved text and files.";
    authUsername.value = currentUser.username;
    authPassword.value = "";
    setAuthStatus("");
    return;
  }

  authTitle.textContent = authMode === "login" ? "Welcome back" : "Create your local account";
  authSubtitle.textContent = authMode === "login"
    ? "Sign in to reopen, copy, and delete your saved shares later."
    : "Create an account to save files and text directly into your history.";
  authSubmit.textContent = authMode === "login" ? "Login" : "Create account";
}

async function loadMe() {
  const response = await fetch("/api/me");
  const result = await response.json();
  currentUser = result.authenticated ? result.user : null;
  updateAuthUI();
}

authTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    authMode = tab.dataset.authMode;
    authTabs.forEach((item) => item.classList.toggle("active", item === tab));
    updateAuthUI();
    setAuthStatus("");
  });
});

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData();
  data.set("username", authUsername.value);
  data.set("password", authPassword.value);

  setAuthStatus(authMode === "login" ? "Signing in..." : "Creating account...");
  const response = await fetch(`/api/auth/${authMode}`, { method: "POST", body: data });
  const result = await response.json();
  if (!response.ok) {
    setAuthStatus(result.error || "Could not continue", true);
    return;
  }

  currentUser = result.user;
  updateAuthUI();
  setAuthStatus(authMode === "login" ? "Signed in." : "Account created.");
});

logoutBtn.addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST" });
  currentUser = null;
  authUsername.value = "";
  authPassword.value = "";
  updateAuthUI();
  setAuthStatus("Logged out.");
});

loadMe();
