const form = document.querySelector("#auth-form");
const message = document.querySelector("#message");
const account = document.querySelector("#account");
const accountEmail = document.querySelector("#account-email");
const loginTab = document.querySelector("#login-tab");
const registerTab = document.querySelector("#register-tab");
const submitButton = document.querySelector("#submit-button");
const password = document.querySelector("#password");
let registerMode = false;

// Der Client sammelt nur das Formular und schickt die Daten an den Server.
// Das eigentliche Passwort-Hashing passiert serverseitig, nicht im Browser.

function showMessage(text, isError = false) {
  message.textContent = text;
  message.className = `message ${isError ? "error" : "success"}`;
}

function setMode(isRegisterMode) {
  registerMode = isRegisterMode;
  loginTab.classList.toggle("active", !registerMode);
  registerTab.classList.toggle("active", registerMode);
  loginTab.setAttribute("aria-selected", String(!registerMode));
  registerTab.setAttribute("aria-selected", String(registerMode));
  submitButton.textContent = registerMode ? "Registrieren" : "Anmelden";
  password.autocomplete = registerMode ? "new-password" : "current-password";
  message.textContent = "";
  message.className = "message";
}

async function request(path, body) {
  // Jede Anfrage an die API wird per POST an den Server gesendet.
  // Dabei werden E-Mail und Passwort als JSON übertragen.
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

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  submitButton.disabled = true;

  // Aus dem Formular werden E-Mail und Passwort gelesen und an die passende API
  // gesendet. Je nach Modus wird entweder registriert oder eingeloggt.
  const data = Object.fromEntries(new FormData(form));
  try {
    const result = await request(registerMode ? "/api/register" : "/api/login", data);
    showMessage(result.message);
    if (!registerMode) showAccount(result.email);
    if (registerMode) {
      form.reset();
      setMode(false);
    }
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    submitButton.disabled = false;
  }
});

function showAccount(email) {
  accountEmail.textContent = email;
  account.classList.remove("hidden");
  form.parentElement.classList.add("hidden");
}

async function checkSession() {
  // Beim Seitenstart prüfen wir, ob bereits eine gültige Session-Cookie existiert.
  // Falls ja, wird der Benutzer direkt als eingeloggt angezeigt.
  const response = await fetch("/api/me", { credentials: "same-origin" });
  if (response.ok) showAccount((await response.json()).email);
}

document.querySelector("#logout-button").addEventListener("click", async () => {
  await request("/api/logout", {});
  account.classList.add("hidden");
  form.parentElement.classList.remove("hidden");
  showMessage("Du wurdest abgemeldet.");
});

loginTab.addEventListener("click", () => setMode(false));
registerTab.addEventListener("click", () => setMode(true));
checkSession();
