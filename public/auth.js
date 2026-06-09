const authTabs = document.querySelectorAll("[data-auth-mode]");
const authTitle = document.querySelector("#authTitle");
const authSubtitle = document.querySelector("#authSubtitle");
const authForm = document.querySelector("#authForm");
const authEmail = document.querySelector("#authEmail");
const authEmailRow = document.querySelector("#authEmailRow");
const authUsername = document.querySelector("#authUsername");
const authUsernameRow = document.querySelector("#authUsernameRow");
const authUsernameLabel = document.querySelector("#authUsernameLabel");
const authPassword = document.querySelector("#authPassword");
const authPasswordRow = document.querySelector("#authPasswordRow");
const rememberRow = document.querySelector("#rememberRow");
const rememberMe = document.querySelector("#rememberMe");
const authSubmit = document.querySelector("#authSubmit");
const logoutBtn = document.querySelector("#logoutBtn");
const forgotPasswordBtn = document.querySelector("#forgotPasswordBtn");
const authHelper = document.querySelector("#authHelper");
const authStatus = document.querySelector("#authStatus");
const socialButtons = document.querySelectorAll(".social-btn");
const socialBlock = document.querySelector(".social-block");

const authModal = document.querySelector("#authModal");
const authModalTitle = document.querySelector("#authModalTitle");
const authModalSubtitle = document.querySelector("#authModalSubtitle");
const authModalClose = document.querySelector("#authModalClose");
const authModalEmail = document.querySelector("#authModalEmail");
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
let modalCooldownEndsAt = 0;
let cooldownTimer = null;

function setHidden(element, hidden) {
  element.classList.toggle("hidden", hidden);
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

function startCooldown(seconds) {
  modalCooldownEndsAt = Date.now() + (seconds * 1000);
  stopCooldown();
  cooldownTimer = window.setInterval(updateCooldownButton, 1000);
  updateCooldownButton();
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

function resetModal() {
  modalMode = "";
  authModalEmail.readOnly = false;
  authModalEmail.value = "";
  authModalCode.value = "";
  authModalPassword.value = "";
  setHidden(authModalPasswordRow, true);
  setModalStatus("");
  stopCooldown();
  authModalSendCode.disabled = false;
  authModalSendCode.textContent = "Send code";
}

function closeModal() {
  authModal.classList.add("hidden");
  authModal.setAttribute("aria-hidden", "true");
  resetModal();
}

function openModal(mode, email = "") {
  modalMode = mode;
  authModal.classList.remove("hidden");
  authModal.setAttribute("aria-hidden", "false");
  authModalEmail.value = email;
  authModalCode.value = "";
  authModalPassword.value = "";
  setModalStatus("");

  if (mode === "signup") {
    authModalTitle.textContent = "Verify your email";
    authModalSubtitle.textContent = "Use the code from your inbox to finish creating your account.";
    authModalSubmit.textContent = "Submit";
    authModalEmail.readOnly = true;
    setHidden(authModalPasswordRow, true);
    stopCooldown();
    authModalSendCode.disabled = false;
    authModalSendCode.textContent = "Send code";
    setModalStatus("Tap Send code to get your verification code.");
  } else {
    authModalTitle.textContent = "Reset your password";
    authModalSubtitle.textContent = "Send a code to your email, then choose a new password.";
    authModalSubmit.textContent = "Reset password";
    authModalEmail.readOnly = false;
    setHidden(authModalPasswordRow, false);
    stopCooldown();
    authModalSendCode.disabled = false;
    authModalSendCode.textContent = "Send code";
  }
}

function updateAuthUI() {
  const signedIn = Boolean(currentUser);
  authTabs.forEach((tab) => tab.classList.toggle("hidden", signedIn));
  authSubmit.classList.toggle("hidden", signedIn);
  logoutBtn.classList.toggle("hidden", !signedIn);
  forgotPasswordBtn.classList.toggle("hidden", signedIn || authMode !== "login");
  rememberRow.classList.toggle("hidden", signedIn || authMode !== "login");
  authEmailRow.classList.toggle("hidden", authMode !== "signup");
  socialBlock.classList.toggle("hidden", signedIn);

  authUsername.disabled = signedIn;
  authEmail.disabled = signedIn;
  authPassword.disabled = signedIn;
  rememberMe.disabled = signedIn;

  if (signedIn) {
    authTitle.textContent = `Signed in as ${currentUser.username}`;
    authSubtitle.textContent = "Your account is ready. Open My History to see saved text and files.";
    authUsername.value = currentUser.username;
    authEmail.value = currentUser.email || "";
    authPassword.value = "";
    rememberMe.checked = false;
    authHelper.textContent = "";
    setAuthStatus("");
    return;
  }

  if (authMode === "signup") {
    authTitle.textContent = "Create your account";
    authSubtitle.textContent = "Sign up once, verify your email, and keep your shares in personal history.";
    authUsernameLabel.textContent = "Username";
    authUsername.placeholder = "yourname";
    authPassword.placeholder = "Create a password";
    authPassword.autocomplete = "new-password";
    authSubmit.textContent = "Create account";
    authHelper.textContent = "After you create the account, we will open the verification popup.";
  } else {
    authTitle.textContent = "Welcome back";
    authSubtitle.textContent = "Sign in with your username or email and password.";
    authUsernameLabel.textContent = "Username or Email";
    authUsername.placeholder = "yourname or you@example.com";
    authPassword.placeholder = "Password";
    authPassword.autocomplete = "current-password";
    authSubmit.textContent = "Login";
    authHelper.textContent = "Use Remember me if you want to stay signed in on this device.";
  }
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
    closeModal();
    authTabs.forEach((item) => item.classList.toggle("active", item === tab));
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
    setAuthStatus("Creating your account...");
  } else {
    data.set("username", authUsername.value.trim());
    data.set("password", authPassword.value);
    data.set("remember_me", rememberMe.checked ? "true" : "false");
    setAuthStatus("Signing you in...");
  }

  const response = await fetch(`/api/auth/${authMode}`, { method: "POST", body: data });
  const result = await response.json();

  if (!response.ok) {
    setAuthStatus(result.error || "Could not continue", true);
    return;
  }

  if (authMode === "signup") {
    openModal("signup", result.email || authEmail.value.trim());
    setAuthStatus(result.message || "Account created. Now send the verification code.");
    return;
  }

  currentUser = result.user;
  updateAuthUI();
  setAuthStatus("Signed in.");
});

authModalSendCode.addEventListener("click", async () => {
  const data = new FormData();
  let endpoint = "";

  if (modalMode === "signup") {
    endpoint = "/api/auth/resend-signup-code";
    data.set("email", authModalEmail.value.trim());
    setModalStatus("Sending another verification code...");
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
    if (retryAfter > 0) {
      startCooldown(retryAfter);
    }
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
  } else if (modalMode === "reset") {
    endpoint = "/api/auth/reset-password";
    data.set("email", authModalEmail.value.trim());
    data.set("code", authModalCode.value.trim());
    data.set("password", authModalPassword.value);
    setModalStatus("Resetting your password...");
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

socialButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const provider = button.dataset.provider || "Social login";
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
