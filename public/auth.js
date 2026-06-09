const authTabs = document.querySelectorAll("[data-auth-mode]");
const authTitle = document.querySelector("#authTitle");
const authSubtitle = document.querySelector("#authSubtitle");
const authForm = document.querySelector("#authForm");
const authUsername = document.querySelector("#authUsername");
const authEmail = document.querySelector("#authEmail");
const authPassword = document.querySelector("#authPassword");
const authCode = document.querySelector("#authCode");
const authEmailRow = document.querySelector("#authEmailRow");
const authCodeRow = document.querySelector("#authCodeRow");
const authSubmit = document.querySelector("#authSubmit");
const authSecondaryBtn = document.querySelector("#authSecondaryBtn");
const authStatus = document.querySelector("#authStatus");
const logoutBtn = document.querySelector("#logoutBtn");

let authMode = "login";
let currentUser = null;
let pendingSignupEmail = "";
let pendingLoginEmail = "";

function setAuthStatus(message, isError = false) {
  authStatus.textContent = message;
  authStatus.classList.toggle("error", isError);
}

function setHidden(element, hidden) {
  element.classList.toggle("hidden", hidden);
}

function updateAuthUI() {
  const signedIn = Boolean(currentUser);
  authTabs.forEach((tab) => tab.classList.toggle("hidden", signedIn));
  authUsername.disabled = signedIn;
  authEmail.disabled = signedIn;
  authPassword.disabled = signedIn;
  authCode.disabled = signedIn;
  authSubmit.classList.toggle("hidden", signedIn);
  logoutBtn.classList.toggle("hidden", !signedIn);

  if (signedIn) {
    authTitle.textContent = `Signed in as ${currentUser.username}`;
    authSubtitle.textContent = "Your account is ready. Open My History to see saved text and files.";
    authUsername.value = currentUser.username;
    authEmail.value = currentUser.email || "";
    authPassword.value = "";
    authCode.value = "";
    setHidden(authEmailRow, false);
    setHidden(authCodeRow, true);
    setHidden(authSecondaryBtn, true);
    setAuthStatus("");
    return;
  }

  const isSignup = authMode === "signup";
  const isEmailCode = authMode === "email-code";
  const awaitingSignupCode = Boolean(pendingSignupEmail);
  const awaitingLoginCode = Boolean(pendingLoginEmail);

  setHidden(authEmailRow, !(isSignup || isEmailCode || awaitingSignupCode || awaitingLoginCode));
  setHidden(authCodeRow, !(awaitingSignupCode || awaitingLoginCode));
  setHidden(authSecondaryBtn, !(awaitingSignupCode || awaitingLoginCode));

  authUsername.parentElement.classList.toggle("hidden", isEmailCode || awaitingSignupCode || awaitingLoginCode);
  authPassword.parentElement.classList.toggle("hidden", isEmailCode || awaitingSignupCode || awaitingLoginCode);

  if (awaitingSignupCode) {
    authTitle.textContent = "Verify your email";
    authSubtitle.textContent = `We sent a code to ${pendingSignupEmail}. Enter it to finish your account setup.`;
    authSubmit.textContent = "Send again";
    authSecondaryBtn.textContent = "Verify code";
    return;
  }

  if (awaitingLoginCode) {
    authTitle.textContent = "Check your inbox";
    authSubtitle.textContent = `We sent a sign-in code to ${pendingLoginEmail}.`;
    authSubmit.textContent = "Send again";
    authSecondaryBtn.textContent = "Sign in";
    return;
  }

  authTitle.textContent = isSignup
    ? "Create and verify your account"
    : isEmailCode
      ? "Sign in with email"
      : "Welcome back";
  authSubtitle.textContent = isSignup
    ? "Create an account, verify your email, and save files or text straight into your history."
    : isEmailCode
      ? "Request a one-time code by email instead of using your password."
      : "Sign in to reopen, copy, and delete your saved shares later.";
  authSubmit.textContent = isSignup ? "Create account" : isEmailCode ? "Send code" : "Login";
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
    pendingSignupEmail = "";
    pendingLoginEmail = "";
    authTabs.forEach((item) => item.classList.toggle("active", item === tab));
    authCode.value = "";
    updateAuthUI();
    setAuthStatus("");
  });
});

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (pendingSignupEmail) {
    const data = new FormData();
    data.set("username", authUsername.value);
    data.set("email", pendingSignupEmail);
    data.set("password", authPassword.value);
    setAuthStatus("Sending a fresh verification code...");
    const response = await fetch("/api/auth/signup", { method: "POST", body: data });
    const result = await response.json();
    setAuthStatus(result.message || result.error || "Could not continue", !response.ok);
    return;
  }

  if (pendingLoginEmail) {
    const data = new FormData();
    data.set("email", pendingLoginEmail);
    setAuthStatus("Sending a fresh sign-in code...");
    const response = await fetch("/api/auth/send-login-code", { method: "POST", body: data });
    const result = await response.json();
    setAuthStatus(result.message || result.error || "Could not continue", !response.ok);
    return;
  }

  const data = new FormData();
  let endpoint = `/api/auth/${authMode === "email-code" ? "send-login-code" : authMode}`;

  if (authMode === "signup") {
    data.set("username", authUsername.value);
    data.set("email", authEmail.value);
    data.set("password", authPassword.value);
    setAuthStatus("Creating account and sending verification code...");
  } else if (authMode === "email-code") {
    data.set("email", authEmail.value);
    setAuthStatus("Sending sign-in code...");
  } else {
    data.set("username", authUsername.value);
    data.set("password", authPassword.value);
    setAuthStatus("Signing in...");
  }

  const response = await fetch(endpoint, { method: "POST", body: data });
  const result = await response.json();
  if (!response.ok) {
    setAuthStatus(result.error || "Could not continue", true);
    return;
  }

  if (authMode === "signup") {
    pendingSignupEmail = result.email || authEmail.value.trim();
    updateAuthUI();
    setAuthStatus(result.message || "Verification code sent.");
    return;
  }

  if (authMode === "email-code") {
    pendingLoginEmail = result.email || authEmail.value.trim();
    updateAuthUI();
    setAuthStatus(result.message || "Sign-in code sent.");
    return;
  }

  currentUser = result.user;
  updateAuthUI();
  setAuthStatus("Signed in.");
});

authSecondaryBtn.addEventListener("click", async () => {
  const data = new FormData();
  let endpoint = "";

  if (pendingSignupEmail) {
    endpoint = "/api/auth/verify-signup";
    data.set("email", pendingSignupEmail);
    data.set("code", authCode.value);
    setAuthStatus("Verifying your account...");
  } else if (pendingLoginEmail) {
    endpoint = "/api/auth/verify-login-code";
    data.set("email", pendingLoginEmail);
    data.set("code", authCode.value);
    setAuthStatus("Signing you in...");
  } else {
    return;
  }

  const response = await fetch(endpoint, { method: "POST", body: data });
  const result = await response.json();
  if (!response.ok) {
    setAuthStatus(result.error || "Could not continue", true);
    return;
  }

  pendingSignupEmail = "";
  pendingLoginEmail = "";
  currentUser = result.user;
  authCode.value = "";
  updateAuthUI();
  setAuthStatus("Signed in.");
});

logoutBtn.addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST" });
  currentUser = null;
  pendingSignupEmail = "";
  pendingLoginEmail = "";
  authUsername.value = "";
  authEmail.value = "";
  authPassword.value = "";
  authCode.value = "";
  updateAuthUI();
  setAuthStatus("Logged out.");
});

loadMe();
