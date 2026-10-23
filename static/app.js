const form = document.querySelector("#auth-form");
const panel = document.querySelector(".panel");
const message = document.querySelector("#message");
const account = document.querySelector("#account");
const accountEmail = document.querySelector("#account-email");
const loginTab = document.querySelector("#login-tab");
const registerTab = document.querySelector("#register-tab");
const submitButton = document.querySelector("#submit-button");
const otpForm = document.querySelector("#otp-form");
const otpInput = document.querySelector("#otp");
const otpSubmitButton = document.querySelector("#otp-submit-button");
const otpCancelButton = document.querySelector("#otp-cancel-button");
const totpSetup = document.querySelector("#totp-setup");
const totpSecret = document.querySelector("#totp-secret");
const totpUri = document.querySelector("#totp-uri");
const resetRequestButton = document.querySelector("#reset-request-button");
const resetRequestForm = document.querySelector("#reset-request-form");
const resetEmail = document.querySelector("#reset-email");
const resetSubmitButton = document.querySelector("#reset-submit-button");
const resetCancelButton = document.querySelector("#reset-cancel-button");
const password = document.querySelector("#password");
const themeSelect = document.querySelector("#theme-select");
const tabs = document.querySelector(".tabs");
const emailVerificationScreen = document.querySelector("#email-verification-screen");
const verificationEmail = document.querySelector("#verification-email");
const emailVerificationCancelButton = document.querySelector(
  "#email-verification-cancel-button"
);

const THEMES = [
  "anime",
  "business",
  "warhammer",
  "steampunk",
  "eurotruck",
  "warframe",
  "anatomical"
];
const DEFAULT_THEME = "anime";
let otpChallengeToken = "";
let emailChallengeToken = "";
let emailConfirmationTimer = null;
let registerMode = false;

async function hashPassword(password) {
  const encoded = new TextEncoder().encode(password);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function setHidden(element, hidden) {
  element.classList.toggle("hidden", hidden);
}

function stopEmailConfirmationPolling() {
  if (emailConfirmationTimer === null) {
    return;
  }
  clearInterval(emailConfirmationTimer);
  emailConfirmationTimer = null;
}

function applyTheme(theme) {
  const selectedTheme = THEMES.includes(theme) ? theme : DEFAULT_THEME;
  document.body.dataset.theme = selectedTheme;
  themeSelect.value = selectedTheme;
  localStorage.setItem("login-theme", selectedTheme);
}

/** Zeigt dem Benutzer eine Erfolgs- oder Fehlermeldung an. */
function showMessage(text, isError = false) {
  message.textContent = text;
  message.className = `message ${isError ? "error" : "success"}`;
}

function clearMessage() {
  showMessage("");
}

/** Wechselt zwischen dem Login- und dem Registrierungsformular. */
function setMode(isRegisterMode) {
  registerMode = isRegisterMode;
  loginTab.classList.toggle("active", !registerMode);
  registerTab.classList.toggle("active", registerMode);
  loginTab.setAttribute("aria-selected", String(!registerMode));
  registerTab.setAttribute("aria-selected", String(registerMode));
  submitButton.textContent = registerMode ? "Registrieren" : "Anmelden";
  password.autocomplete = registerMode ? "new-password" : "current-password";
  clearMessage();
}

function showResetForm() {
  setHidden(form, true);
  setHidden(resetRequestButton, true);
  setHidden(resetRequestForm, false);
  resetEmail.value = document.querySelector("#email").value;
  clearMessage();
}

function hideResetForm() {
  setHidden(form, false);
  setHidden(resetRequestButton, false);
  setHidden(resetRequestForm, true);
  clearMessage();
}

function showLoginForm() {
  stopEmailConfirmationPolling();
  setHidden(otpForm, true);
  setHidden(emailVerificationScreen, true);
  setHidden(resetRequestForm, true);
  setHidden(form, false);
  setHidden(tabs, false);
  setHidden(resetRequestButton, false);
  otpChallengeToken = "";
  emailChallengeToken = "";
  otpInput.value = "";
  clearMessage();
}

function showOtpForm(result) {
  setHidden(emailVerificationScreen, true);
  setHidden(form, true);
  setHidden(resetRequestButton, true);
  otpChallengeToken = result.challenge_token;
  totpSecret.textContent = result.totp_secret;
  totpUri.textContent = result.totp_uri;
  setHidden(totpSetup, false);
  setHidden(otpForm, false);
  message.textContent = result.message || "Geben Sie den Code aus Ihrer Authenticator-App ein.";
  message.className = "message success";
}

function showEmailVerificationScreen(email) {
  stopEmailConfirmationPolling();
  setHidden(form, true);
  setHidden(otpForm, true);
  setHidden(resetRequestButton, true);
  setHidden(tabs, true);
  clearMessage();
  verificationEmail.textContent = email;
  setHidden(emailVerificationScreen, false);
}

function waitForEmailConfirmation() {
  stopEmailConfirmationPolling();
  emailConfirmationTimer = setInterval(async () => {
    try {
      const response = await fetch(
        `/api/login-email-status?challenge=${encodeURIComponent(emailChallengeToken)}`,
        { credentials: "same-origin" }
      );
      if (!response.ok || response.status === 202) return;
      const result = await response.json();
      stopEmailConfirmationPolling();
      showOtpForm(result);
    } catch (error) {
      stopEmailConfirmationPolling();
      showMessage("Die E-Mail-Bestätigung konnte nicht geprüft werden.", true);
    }
  }, 2000);
}

/** Sendet eine JSON-POST-Anfrage an einen API-Endpunkt. */
async function request(path, body = {}) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Etwas ist schiefgelaufen.");
  return data;
}

/** Verarbeitet das Absenden des Login- oder Registrierungsformulars. */
async function handleSubmit(event) {
  event.preventDefault();
  submitButton.disabled = true;

  const data = Object.fromEntries(new FormData(form));
  try {
    data.password = await hashPassword(data.password);
    const result = await request(registerMode ? "/api/register" : "/api/login", data);
    showMessage(result.message);
    if (!registerMode && result.email_confirmation_required) {
      emailChallengeToken = result.email_challenge;
      showEmailVerificationScreen(data.email);
      waitForEmailConfirmation();
    } else if (!registerMode) {
      showAccount(result.email);
    }
    if (registerMode) {
      form.reset();
      setMode(false);
    }

  } catch (error) {
    showMessage(error.message, true);
  } finally {
    submitButton.disabled = false;
  }
}

async function handleOtpSubmit(event) {
  event.preventDefault();
  otpSubmitButton.disabled = true;
  try {
    const result = await request("/api/verify-login-otp", {
      challenge_token: otpChallengeToken,
      otp: otpInput.value
    });
    showMessage(result.message);
    showAccount(result.email);
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    otpSubmitButton.disabled = false;
  }
}

async function handleResetRequest(event) {
  event.preventDefault();
  resetSubmitButton.disabled = true;
  try {
    const result = await request("/api/request-password-reset", {
      email: resetEmail.value
    });
    showMessage(result.message);
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    resetSubmitButton.disabled = false;
  }
}

/** Blendet das Formular aus und zeigt das angemeldete Konto an. */
function showAccount(email) {
  accountEmail.textContent = email;
  setHidden(account, false);
  setHidden(panel, true);
}

/** Prüft beim Laden der Seite, ob bereits eine gültige Session besteht. */
async function checkSession() {
  const response = await fetch("/api/me", { credentials: "same-origin" });
  if (response.ok) showAccount((await response.json()).email);
}

/** Meldet den Benutzer ab und zeigt anschließend wieder das Formular an. */
async function handleLogout() {
  await request("/api/logout", {});
  setHidden(account, true);
  setHidden(panel, false);
  showMessage("Du wurdest abgemeldet.");
}

/** Aktiviert den Login-Modus, wenn der Login-Tab ausgewählt wird. */
function handleLoginTab() {
  setMode(false);
}

/** Aktiviert den Registrierungsmodus, wenn der Registrierungs-Tab ausgewählt wird. */
function handleRegisterTab() {
  setMode(true);
}

form.addEventListener("submit", handleSubmit);
document.querySelector("#logout-button").addEventListener("click", handleLogout);
loginTab.addEventListener("click", handleLoginTab);
registerTab.addEventListener("click", handleRegisterTab);
resetRequestButton.addEventListener("click", showResetForm);
resetRequestForm.addEventListener("submit", handleResetRequest);
resetCancelButton.addEventListener("click", hideResetForm);
otpForm.addEventListener("submit", handleOtpSubmit);
otpCancelButton.addEventListener("click", showLoginForm);
emailVerificationCancelButton.addEventListener("click", showLoginForm);
themeSelect.addEventListener("change", (event) => {
  const selectedTheme = event.currentTarget.value;
  applyTheme(selectedTheme);
});
applyTheme(localStorage.getItem("login-theme") || DEFAULT_THEME);
checkSession();
