"use strict";
// Admin page: talks to /api with the session cookie and the session's CSRF token.
// Everything is written with textContent, never as HTML.
(function () {
  const $ = (id) => document.getElementById(id);
  let csrf = "";
  let links = [];

  function say(text, kind) {
    const box = $("message");
    box.textContent = text || "";
    box.className = "notice " + (kind || "ok");
    box.hidden = !text;
  }

  async function call(method, path, body) {
    const res = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: Object.assign({ "X-CSRF-Token": csrf }, body ? { "Content-Type": "application/json" } : {}),
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 401) {
      window.location.assign("/login");
      throw new Error("signed out");
    }
    let data = {};
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) throw new Error(data.error || "Request failed (" + res.status + ")");
    return data;
  }

  const isNumber = (s) => /^\d+$/.test(s);
  function order(a, b) {
    const an = isNumber(a.slug), bn = isNumber(b.slug);
    if (an !== bn) return an ? 1 : -1;
    return an ? Number(a.slug) - Number(b.slug) : a.slug.localeCompare(b.slug);
  }

  function button(text, onClick, cls) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = text;
    b.className = cls || "quiet";
    b.addEventListener("click", onClick);
    return b;
  }

  function render() {
    const needle = $("filter").value.trim().toLowerCase();
    const body = $("links");
    body.replaceChildren();
    const shown = links.filter((l) => !needle || l.slug.toLowerCase().includes(needle) || l.url.toLowerCase().includes(needle));
    for (const link of shown.sort(order)) {
      const short = window.location.origin + "/" + encodeURIComponent(link.slug);
      const tr = document.createElement("tr");

      const a = document.createElement("a");
      a.href = short;
      a.textContent = "/" + link.slug;
      a.rel = "noreferrer noopener";
      a.target = "_blank";
      const c1 = document.createElement("td");
      c1.append(a);

      const c2 = document.createElement("td");
      c2.className = "target";
      const c3 = document.createElement("td");
      c3.className = "actions";

      const show = () => {
        c2.textContent = link.url;
        c2.title = link.url;
        c3.replaceChildren(
          button("Copy", async () => {
            try { await navigator.clipboard.writeText(short); say("Copied " + short); } catch (e) { say(short); }
          }),
          button("Edit", edit),
          button("Delete", askDelete, "quiet danger")
        );
      };

      // Editing and deleting happen in the row itself (no browser dialogs).
      const edit = () => {
        const input = document.createElement("input");
        input.type = "text";
        input.maxLength = 2048;
        input.value = link.url;
        input.setAttribute("aria-label", "New target for /" + link.slug);
        const save = async () => {
          const next = input.value.trim();
          if (!next || next === link.url) return show();
          try {
            await call("PUT", "/api/links/" + encodeURIComponent(link.slug), { url: next });
            say("Changed /" + link.slug);
            await load();
          } catch (e) { say(e.message, "error"); }
        };
        input.addEventListener("keydown", (event) => {
          if (event.key === "Enter") save();
        });
        c2.title = "";
        c2.replaceChildren(input);
        c3.replaceChildren(button("Save", save, ""), button("Cancel", show));
        input.focus();
      };

      const askDelete = () => {
        const question = document.createElement("span");
        question.textContent = "Delete? ";
        c3.replaceChildren(
          question,
          button("Yes, delete", async () => {
            try {
              await call("DELETE", "/api/links/" + encodeURIComponent(link.slug));
              say("Deleted /" + link.slug);
              await load();
            } catch (e) { say(e.message, "error"); }
          }, "quiet danger"),
          button("No", show)
        );
      };

      show();
      tr.append(c1, c2, c3);
      body.append(tr);
    }
    $("count").textContent = shown.length + " of " + links.length + " links";
  }

  async function load() {
    links = (await call("GET", "/api/links")).links;
    render();
  }

  $("filter").addEventListener("input", render);

  $("paste").addEventListener("click", async () => {
    try { $("url").value = await navigator.clipboard.readText(); } catch (e) { say("The browser did not allow reading the clipboard.", "error"); }
  });

  $("add-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const made = await call("POST", "/api/links", { slug: $("slug").value.trim(), url: $("url").value.trim() });
      $("slug").value = "";
      $("url").value = "";
      say("Created " + made.short_url);
      await load();
    } catch (e) { say(e.message, "error"); }
  });

  $("password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await call("POST", "/account/password", {
        current: $("current").value,
        password: $("password").value,
        password2: $("password2").value,
      });
      event.target.reset();
      say("Password changed. Other browsers are signed out.");
      await start();
    } catch (e) { say(e.message, "error"); }
  });

  async function start() {
    const session = await call("GET", "/api/session");
    csrf = session.csrf || "";
    $("logout-csrf").value = csrf;
    $("who").textContent = session.username || "";
    $("pw-username").value = session.username || "";
    await load();
  }

  start().catch((e) => say(e.message, "error"));
})();
