const form = document.querySelector("#reset-form");
const password = document.querySelector("#password");
const confirmation = document.querySelector("#password-confirmation");
const submitButton = document.querySelector("#reset-submit-button");
const message = document.querySelector("#message");
const token = new URLSearchParams(window.location.search).get("token");
const THEMES = [
  "anime",
  "business",
  "warhammer",
  "steampunk",
  "eurotruck",
  "warframe",
  "anatomical"
];

const savedTheme = localStorage.getItem("login-theme");
if (THEMES.includes(savedTheme)) {
  document.body.dataset.theme = savedTheme;
}

function showMessage(text, isError = false) {
  message.textContent = text;
  message.className = `message ${isError ? "error" : "success"}`;
}

async function hashPassword(password) {
  const encoded = new TextEncoder().encode(password);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function handleSubmit(event) {
  event.preventDefault();
  if (!token) {
    showMessage("Der Reset-Link ist ungültig oder unvollständig.", true);
    return;
  }
  if (password.value !== confirmation.value) {
    showMessage("Die Passwörter stimmen nicht überein.", true);
    return;
  }

  submitButton.disabled = true;
  try {
    const passwordHash = await hashPassword(password.value);
    const response = await fetch("/api/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, password: passwordHash })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Etwas ist schiefgelaufen.");
    form.classList.add("hidden");
    showMessage(data.message);
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    submitButton.disabled = false;
  }
}

form.addEventListener("submit", handleSubmit);
