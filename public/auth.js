const authTabs = document.querySelectorAll("[data-auth-mode]");
const pageTitle = document.querySelector("#pageTitle");
const pageSubtitle = document.querySelector("#pageSubtitle");
const authTitle = document.querySelector("#authTitle");
const authSubtitle = document.querySelector("#authSubtitle");
const authForm = document.querySelector("#authForm");
const authEmail = document.querySelector("#authEmail");
const authEmailRow = document.querySelector("#authEmailRow");
const authUsername = document.querySelector("#authUsername");
const authUsernameLabel = document.querySelector("#authUsernameLabel");
const authPassword = document.querySelector("#authPassword");
const authCaptchaRow = document.querySelector("#authCaptchaRow");
const authCaptchaPrompt = document.querySelector("#authCaptchaPrompt");
const authCaptchaAnswer = document.querySelector("#authCaptchaAnswer");
const rememberRow = document.querySelector("#rememberRow");
const rememberMe = document.querySelector("#rememberMe");
const authSubmit = document.querySelector("#authSubmit");
const logoutBtn = document.querySelector("#logoutBtn");
const forgotPasswordBtn = document.querySelector("#forgotPasswordBtn");
const authHelper = document.querySelector("#authHelper");
const authStatus = document.querySelector("#authStatus");
const socialButtons = document.querySelectorAll(".social-btn");
const socialBlock = document.querySelector(".social-block");
const profilePanel = document.querySelector("#profilePanel");
const profileUsername = document.querySelector("#profileUsername");
const profileEmail = document.querySelector("#profileEmail");
const profileLogoutBtn = document.querySelector("#profileLogoutBtn");
const passwordToggles = document.querySelectorAll("[data-toggle-password]");

const authModal = document.querySelector("#authModal");
const authModalTitle = document.querySelector("#authModalTitle");
const authModalSubtitle = document.querySelector("#authModalSubtitle");
const authModalClose = document.querySelector("#authModalClose");
const authModalEmailRow = document.querySelector("#authModalEmailRow");
const authModalEmail = document.querySelector("#authModalEmail");
const authModalCodeRow = document.querySelector("#authModalCodeRow");
const authModalCode = document.querySelector("#authModalCode");
const authModalPasswordRow = document.querySelector("#authModalPasswordRow");
const authModalPassword = document.querySelector("#authModalPassword");
const authModalSendCode = document.querySelector("#authModalSendCode");
const authModalSubmit = document.querySelector("#authModalSubmit");
const authModalStatus = document.querySelector("#authModalStatus");

const RESEND_COOLDOWN_SECONDS = 120;
const params = new URLSearchParams(window.location.search);

let authMode = "login";
let currentUser = null;
let modalMode = "";
let resetVerifiedToken = "";
let modalCooldownEndsAt = 0;
let cooldownTimer = null;
let authCaptchaToken = "";

function goHome() {
  window.location.href = "/";
}

function setStatus(target, message, isError = false) {
  target.textContent = message;
  target.classList.toggle("error", isError);
}

function setAuthStatus(message, isError = false) {
  setStatus(authStatus, message, isError);
}

function setModalStatus(message, isError = false) {
  setStatus(authModalStatus, message, isError);
}

function setHidden(element, hidden) {
  element.classList.toggle("hidden", hidden);
}

function setAuthCaptcha(challenge) {
  authCaptchaToken = challenge?.token || "";
  authCaptchaPrompt.textContent = challenge?.prompt || "Solve the challenge to continue.";
  authCaptchaAnswer.value = "";
  setHidden(authCaptchaRow, !authCaptchaToken);
}

async function loadAuthCaptcha(scope) {
  const response = await fetch(`/api/captcha?scope=${encodeURIComponent(scope)}`);
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || "Could not load CAPTCHA");
  }
  setAuthCaptcha(result);
}

function stopCooldown() {
  if (cooldownTimer) {
    window.clearInterval(cooldownTimer);
    cooldownTimer = null;
  }
}

function updateCooldownButton() {
  const remaining = Math.max(0, Math.ceil((modalCooldownEndsAt - Date.now()) / 1000));
  if (!remaining) {
    stopCooldown();
    authModalSendCode.disabled = false;
    authModalSendCode.textContent = "Send code";
    return;
  }
  authModalSendCode.disabled = true;
  authModalSendCode.textContent = `Send again in ${remaining}s`;
}

function startCooldown(seconds) {
  modalCooldownEndsAt = Date.now() + (seconds * 1000);
  stopCooldown();
  cooldownTimer = window.setInterval(updateCooldownButton, 1000);
  updateCooldownButton();
}

function resetModal() {
  modalMode = "";
  resetVerifiedToken = "";
  authModalEmail.value = "";
  authModalCode.value = "";
  authModalPassword.value = "";
  authModalEmail.readOnly = false;
  authModalSendCode.classList.remove("hidden");
  authModalSendCode.disabled = false;
  authModalSendCode.textContent = "Send code";
  authModalSubmit.textContent = "Submit";
  setHidden(authModalEmailRow, false);
  setHidden(authModalCodeRow, false);
  setHidden(authModalPasswordRow, true);
  stopCooldown();
  setModalStatus("");
}

function closeModal() {
  authModal.classList.add("hidden");
  authModal.setAttribute("aria-hidden", "true");
  resetModal();
}

function openModal(mode, email = "") {
  resetModal();
  modalMode = mode;
  authModal.classList.remove("hidden");
  authModal.setAttribute("aria-hidden", "false");
  authModalEmail.value = email;

  if (mode === "signup") {
    authModalTitle.textContent = "Verify your email";
    authModalSubtitle.textContent = "Use the code from your inbox to finish creating your account.";
    authModalSubmit.textContent = "Submit";
    authModalEmail.readOnly = true;
    setModalStatus("Tap Send code to get your verification code.");
  } else {
    authModalTitle.textContent = "Reset your password";
    authModalSubtitle.textContent = "Send a code to your email, then verify it.";
    authModalSubmit.textContent = "Verify code";
    authModalEmail.readOnly = false;
  }
}

function updateAuthUI() {
  const signedIn = Boolean(currentUser);
  authTabs.forEach((tab) => tab.classList.toggle("hidden", signedIn));
  authForm.classList.toggle("hidden", signedIn);
  profilePanel.classList.toggle("hidden", !signedIn);
  logoutBtn.classList.add("hidden");
  forgotPasswordBtn.classList.toggle("hidden", signedIn || authMode !== "login");
  rememberRow.classList.toggle("hidden", authMode !== "login");
  authEmailRow.classList.toggle("hidden", authMode !== "signup");
  socialBlock.classList.toggle("hidden", false);

  if (signedIn) {
    setAuthCaptcha(null);
    pageTitle.textContent = "Your account";
    pageSubtitle.textContent = "This page now shows your profile instead of the sign-in form.";
    authTitle.textContent = `Your profile`;
    authSubtitle.textContent = "You are signed in. Open your history or jump back home to create a new private share.";
    profileUsername.value = currentUser.username;
    profileEmail.value = currentUser.email || "No email saved";
    authHelper.textContent = "";
    setAuthStatus("");
    return;
  }

  if (authMode === "signup") {
    pageTitle.textContent = "Sign in or create an account";
    pageSubtitle.textContent = "Accounts are optional. Use one when you want your text snippets and files saved into personal history.";
    authTitle.textContent = "Create your account";
    authSubtitle.textContent = "Sign up once, verify your email, and keep your shares in personal history.";
    authUsernameLabel.textContent = "Username";
    authUsername.placeholder = "yourname";
    authPassword.placeholder = "Create a password";
    authPassword.autocomplete = "new-password";
    authSubmit.textContent = "Create account";
    authHelper.textContent = "Nothing is saved until your verification code is correct.";
    if (!authCaptchaToken) {
      loadAuthCaptcha("signup").catch((error) => setAuthStatus(error.message || "Could not load CAPTCHA", true));
    }
  } else {
    pageTitle.textContent = "Sign in or create an account";
    pageSubtitle.textContent = "Accounts are optional. Use one when you want your text snippets and files saved into personal history.";
    authTitle.textContent = "Welcome back";
    authSubtitle.textContent = "Sign in with your username or email and password.";
    authUsernameLabel.textContent = "Username or Email";
    authUsername.placeholder = "yourname or you@example.com";
    authPassword.placeholder = "Password";
    authPassword.autocomplete = "current-password";
    authSubmit.textContent = "Login";
    authHelper.textContent = "Use Remember me if you want to stay signed in on this device.";
    setAuthCaptcha(null);
  }

  authUsername.disabled = false;
  authEmail.disabled = false;
  authPassword.disabled = false;
  rememberMe.disabled = false;
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
    closeModal();
    setAuthStatus("");
    updateAuthUI();
  });
});

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setAuthStatus("");

  const data = new FormData();

  if (authMode === "signup") {
    data.set("email", authEmail.value.trim());
    data.set("username", authUsername.value.trim());
    data.set("password", authPassword.value);
    data.set("captcha_token", authCaptchaToken);
    data.set("captcha_answer", authCaptchaAnswer.value.trim());
    setAuthStatus("Preparing your signup...");
  } else {
    data.set("username", authUsername.value.trim());
    data.set("password", authPassword.value);
    data.set("remember_me", rememberMe.checked ? "true" : "false");
    data.set("captcha_token", authCaptchaToken);
    data.set("captcha_answer", authCaptchaAnswer.value.trim());
    setAuthStatus("Signing you in...");
  }

  const response = await fetch(`/api/auth/${authMode}`, { method: "POST", body: data });
  const result = await response.json();

  if (authMode === "signup" && result.requires_verification) {
    openModal("signup", result.email || authEmail.value.trim());
    setAuthStatus(result.message || "Complete your verification to finish creating the account.");
    return;
  }

  if (!response.ok) {
    if (result.captcha_required) setAuthCaptcha(result);
    setAuthStatus(result.error || "Could not continue", true);
    return;
  }

  if (authMode === "signup") {
    openModal("signup", result.email || authEmail.value.trim());
    setAuthStatus(result.message || "Now send the verification code.");
    return;
  }

  currentUser = result.user;
  updateAuthUI();
  setAuthStatus("Signed in.");
  window.setTimeout(goHome, 250);
});

authModalSendCode.addEventListener("click", async () => {
  const data = new FormData();
  let endpoint = "";

  if (modalMode === "signup") {
    endpoint = "/api/auth/resend-signup-code";
    data.set("email", authModalEmail.value.trim());
    setModalStatus("Sending verification code...");
  } else if (modalMode === "reset") {
    endpoint = "/api/auth/send-password-reset";
    data.set("email", authModalEmail.value.trim());
    setModalStatus("Sending reset code...");
  } else {
    return;
  }

  const response = await fetch(endpoint, { method: "POST", body: data });
  const result = await response.json();

  if (!response.ok) {
    const retryAfter = Number(result.retry_after || 0);
    if (retryAfter > 0) startCooldown(retryAfter);
    setModalStatus(result.error || "Could not send code", true);
    return;
  }

  startCooldown(Number(result.cooldown_seconds || RESEND_COOLDOWN_SECONDS));
  setModalStatus(result.message || "Code sent.");
});

authModalSubmit.addEventListener("click", async () => {
  const data = new FormData();
  let endpoint = "";

  if (modalMode === "signup") {
    endpoint = "/api/auth/verify-signup";
    data.set("email", authModalEmail.value.trim());
    data.set("code", authModalCode.value.trim());
    setModalStatus("Verifying your account...");
  } else if (modalMode === "reset" && !resetVerifiedToken) {
    endpoint = "/api/auth/verify-reset-code";
    data.set("email", authModalEmail.value.trim());
    data.set("code", authModalCode.value.trim());
    setModalStatus("Verifying reset code...");
  } else if (modalMode === "reset") {
    endpoint = "/api/auth/reset-password";
    data.set("token", resetVerifiedToken);
    data.set("password", authModalPassword.value);
    setModalStatus("Saving your new password...");
  } else {
    return;
  }

  const response = await fetch(endpoint, { method: "POST", body: data });
  const result = await response.json();

  if (!response.ok) {
    setModalStatus(result.error || "Could not continue", true);
    return;
  }

  if (modalMode === "signup") {
    currentUser = result.user;
    closeModal();
    updateAuthUI();
    setAuthStatus("Account verified and signed in.");
    window.setTimeout(goHome, 250);
    return;
  }

  if (!resetVerifiedToken) {
    resetVerifiedToken = result.token || "";
    authModalSubtitle.textContent = "Code verified. Now enter your new password.";
    authModalSubmit.textContent = "Save password";
    authModalEmail.readOnly = true;
    setHidden(authModalCodeRow, true);
    setHidden(authModalPasswordRow, false);
    authModalSendCode.classList.add("hidden");
    setModalStatus("Reset code verified.");
    return;
  }

  const resetEmail = authModalEmail.value.trim();
  closeModal();
  authMode = "login";
  authTabs.forEach((item) => item.classList.toggle("active", item.dataset.authMode === "login"));
  authUsername.value = resetEmail;
  authPassword.value = "";
  updateAuthUI();
  setAuthStatus(result.message || "Password reset complete. Sign in with your new password.");
});

forgotPasswordBtn.addEventListener("click", () => {
  openModal("reset", "");
});

authModalClose.addEventListener("click", closeModal);

logoutBtn.addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST" });
  currentUser = null;
  authEmail.value = "";
  authUsername.value = "";
  authPassword.value = "";
  rememberMe.checked = false;
  updateAuthUI();
  setAuthStatus("Logged out.");
});

profileLogoutBtn.addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST" });
  currentUser = null;
  authEmail.value = "";
  authUsername.value = "";
  authPassword.value = "";
  rememberMe.checked = false;
  updateAuthUI();
  setAuthStatus("Logged out.");
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

socialButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const provider = button.dataset.provider || "Social login";
    if (provider === "Google") {
      window.location.href = "/api/auth/google/start";
      return;
    }
    setAuthStatus(`${provider} login icon added. The real ${provider} sign-in still needs OAuth keys on the server.`, true);
  });
});

loadMe();

const requestedMode = params.get("mode");
if (requestedMode === "signup" || requestedMode === "login") {
  authMode = requestedMode;
  authTabs.forEach((item) => item.classList.toggle("active", item.dataset.authMode === requestedMode));
  updateAuthUI();
}

const authError = params.get("error");
if (authError) {
  setAuthStatus(authError, true);
}
