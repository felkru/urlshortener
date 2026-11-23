"use strict";
// The few server-rendered pages (login, first-time setup, messages). No inline script or style,
// so the strict Content-Security-Policy holds; every value is escaped.

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function layout(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="robots" content="noindex, nofollow" />
    <title>${esc(title)} - URL Shortener</title>
    <link href="/public/style.css" rel="stylesheet" />
  </head>
  <body>
    <main class="narrow">
${body}
    </main>
  </body>
</html>
`;
}

function notice(message, kind = "error") {
  return message ? `      <p class="notice ${kind}" role="alert">${esc(message)}</p>\n` : "";
}

function loginPage({ error, username } = {}) {
  return layout(
    "Sign in",
    `      <h1>URL Shortener</h1>
${notice(error)}      <form method="post" action="/login" class="card">
        <label for="username">User name</label>
        <input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="64" required autofocus value="${esc(username)}" />
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" maxlength="128" required />
        <button type="submit">Sign in</button>
      </form>`
  );
}

function setupPage({ token, error, username, min, max }) {
  return layout(
    "Set up the login",
    `      <h1>Set up the login</h1>
      <p>This page works once: it creates the one login for this shortener and then closes for good.</p>
${notice(error)}      <form method="post" action="/setup" class="card">
        <input type="hidden" name="token" value="${esc(token)}" />
        <label for="username">User name</label>
        <input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="64" required value="${esc(username || "felix")}" />
        <label for="password">New password (${min} to ${max} characters)</label>
        <input id="password" name="password" type="password" autocomplete="new-password" minlength="${min}" maxlength="${max}" required />
        <label for="password2">Repeat the password</label>
        <input id="password2" name="password2" type="password" autocomplete="new-password" minlength="${min}" maxlength="${max}" required />
        <button type="submit">Create login</button>
      </form>`
  );
}

function messagePage(title, message) {
  return layout(title, `      <h1>${esc(title)}</h1>\n      <p>${esc(message)}</p>\n      <p><a href="/">Back</a></p>`);
}

module.exports = { esc, loginPage, setupPage, messagePage };
