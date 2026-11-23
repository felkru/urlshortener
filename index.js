"use strict";
require("dotenv").config();
const path = require("path");
const express = require("express");
const auth = require("./lib/auth");
const rules = require("./lib/validate");
const pages = require("./lib/pages");

const USERNAME_RE = /^[a-z0-9][a-z0-9._@+-]{0,63}$/;

function createApp({ store, config }) {
  const origin = config.publicOrigin;
  const ownHost = new URL(origin).host;
  const log = config.log || console.log;
  const sessions = new auth.Sessions(config.sessionSecret);
  const tokenEnabled = typeof config.apiToken === "string" && config.apiToken.length >= 32;
  const setupEnabled = typeof config.setupToken === "string" && config.setupToken.length >= 32;
  const failures = new auth.FailureLimiter(config.failureLimits);
  const redirectRate = new auth.RateWindow(config.redirectsPerMinute || 240, 60_000);
  const adminRate = new auth.RateWindow(config.adminPerMinute || 120, 60_000);

  const app = express();
  app.disable("x-powered-by");
  app.disable("etag");
  app.set("query parser", "simple");

  const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

  // ---- every response: security headers, and who is asking --------------------------------
  app.use((req, res, next) => {
    res.set({
      "Content-Security-Policy":
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      // same-origin, not no-referrer: with no-referrer browsers send "Origin: null" on form posts,
      // and the origin check below needs the real one. Other sites still get no referrer.
      "Referrer-Policy": "same-origin",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), clipboard-read=(self), clipboard-write=(self)",
      "Strict-Transport-Security": "max-age=31536000",
      "Cache-Control": "no-store",
    });
    req.clientIp = auth.clientIp(req);
    req.ipKey = auth.ipKey(req.clientIp);
    next();
  });

  function tooMany(res, seconds, asPage) {
    res.set("Retry-After", String(seconds));
    res.status(429);
    const text = `Too many attempts. Try again in ${seconds} seconds.`;
    return asPage ? res.send(pages.messagePage("Slow down", text)) : res.json({ error: text, retry_after: seconds });
  }

  const limit = (rate) => (req, res, next) => {
    const seconds = rate.hit(req.ipKey);
    return seconds ? tooMany(res, seconds, false) : next();
  };

  // ---- who is signed in: a bearer token (agents) or the session cookie (browser) ------------
  function identify(req, res, next) {
    req.auth = null;
    const header = req.headers.authorization;
    if (typeof header === "string" && header) {
      const wait = failures.waitMs(req.ipKey);
      if (wait) return tooMany(res, Math.ceil(wait / 1000), false);
      const m = /^Bearer ([A-Za-z0-9._~+/=-]{1,256})$/.exec(header);
      if (m && tokenEnabled && auth.safeEqual(m[1], config.apiToken)) {
        req.auth = { kind: "token" };
        return next();
      }
      failures.fail(req.ipKey);
      log(`auth: wrong API token from ${req.clientIp}`);
      res.set("WWW-Authenticate", "Bearer");
      return res.status(401).json({ error: "invalid token" });
    }
    const cookie = auth.readCookie(req, auth.COOKIE_NAME);
    if (cookie && store.user) {
      const session = sessions.read(cookie, store.user.session_epoch || 0);
      if (session) req.auth = { kind: "session", csrf: session.csrf, username: store.user.username };
    }
    next();
  }

  // A browser request that changes something must come from our own pages: the Origin header
  // (or Sec-Fetch-Site) has to say so, and it has to carry the session's CSRF token.
  function sameOrigin(req) {
    const o = req.headers.origin;
    if (typeof o === "string" && o && o !== "null") return o === origin;
    // No usable Origin (some privacy settings send "null"): the browser-set Sec-Fetch-Site decides.
    const site = req.headers["sec-fetch-site"];
    if (typeof site === "string" && site) return site === "same-origin";
    return o !== "null"; // neither header: not a browser, so there is no victim's cookie to ride on
  }

  function requireCsrf(req, res, next) {
    if (req.method === "GET" || req.method === "HEAD" || req.auth.kind !== "session") return next();
    const sent = req.headers["x-csrf-token"] || (req.body && req.body._csrf);
    if (!sameOrigin(req) || typeof sent !== "string" || !auth.safeEqual(sent, req.auth.csrf)) {
      return res.status(403).json({ error: "request did not come from the shortener's own page" });
    }
    next();
  }

  function requireSessionPage(req, res, next) {
    if (req.auth && req.auth.kind === "session") return next();
    res.redirect(303, "/login");
  }

  app.use("/public", express.static(path.join(__dirname, "public"), { index: false, dotfiles: "ignore", maxAge: "10m" }));
  app.use("/public", (req, res) => res.status(404).json({ error: "not found" }));

  app.use(express.urlencoded({ extended: false, limit: "8kb", parameterLimit: 20 }));
  app.use(express.json({ limit: "8kb" }));

  // ---- pages --------------------------------------------------------------------------------
  app.get("/", limit(adminRate), identify, (req, res) => {
    const host = String(req.headers.host || "").toLowerCase();
    if (host !== ownHost && !/^localhost(:\d+)?$/.test(host)) {
      return res.redirect(301, "https://www.felix-krueckel.com/");
    }
    if (!req.auth || req.auth.kind !== "session") return res.redirect(303, "/login");
    res.sendFile(path.join(__dirname, "views", "admin.html"), { cacheControl: false });
  });

  app.get("/login", limit(adminRate), identify, (req, res) => {
    if (!sessions.enabled) return res.status(503).send(pages.messagePage("Login is switched off", "The server has no session secret set."));
    if (req.auth && req.auth.kind === "session") return res.redirect(303, "/");
    res.send(pages.loginPage());
  });

  app.post("/login", limit(adminRate), wrap(async (req, res) => {
    if (!sessions.enabled) return res.status(503).send(pages.messagePage("Login is switched off", "The server has no session secret set."));
    if (!sameOrigin(req)) return res.status(403).send(pages.messagePage("Not allowed", "Please sign in from the shortener's own page."));
    const wait = failures.waitMs(req.ipKey);
    if (wait) return tooMany(res, Math.ceil(wait / 1000), true);
    const username = typeof req.body.username === "string" ? req.body.username.trim().toLowerCase() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    // Counted before the check, so a burst of parallel tries cannot slip past the limit.
    failures.fail(req.ipKey);
    const user = await store.refreshUser();
    const fits = username.length <= 64 && password.length > 0 && password.length <= auth.PASSWORD_MAX;
    const passwordOk = await auth.verifyPassword(fits ? password : "", user && user.password);
    const ok = Boolean(user) && fits && passwordOk && auth.safeEqual(username, user.username);
    if (!ok) {
      log(`auth: failed login from ${req.clientIp}`);
      const locked = failures.waitMs(req.ipKey);
      const hint = locked ? ` Too many tries: wait ${Math.ceil(locked / 1000)} seconds.` : "";
      if (locked) res.set("Retry-After", String(Math.ceil(locked / 1000)));
      return res.status(401).send(pages.loginPage({ error: "Wrong user name or password." + hint, username: username.slice(0, 64) }));
    }
    failures.success(req.ipKey);
    log(`auth: login from ${req.clientIp}`);
    sessions.setCookie(res, sessions.issue(user.session_epoch || 0));
    res.redirect(303, "/");
  }));

  // First-time setup: only while no user exists, and only with the setup token from the
  // server's environment. Afterwards both routes answer 404 like any unknown page.
  async function setupOpen(req, res, token) {
    const notFound = () => { res.status(404).json({ error: "not found" }); return false; };
    if (!sessions.enabled || !setupEnabled) return notFound();
    const wait = failures.waitMs(req.ipKey);
    if (wait) { tooMany(res, Math.ceil(wait / 1000), true); return false; }
    if (await store.refreshUser()) return notFound();
    if (typeof token !== "string" || !auth.safeEqual(token, config.setupToken)) {
      failures.fail(req.ipKey);
      return notFound();
    }
    return true;
  }

  app.get("/setup", limit(adminRate), wrap(async (req, res) => {
    if (!(await setupOpen(req, res, req.query.token))) return;
    res.send(pages.setupPage({ token: req.query.token, min: auth.PASSWORD_MIN, max: auth.PASSWORD_MAX }));
  }));

  app.post("/setup", limit(adminRate), wrap(async (req, res) => {
    if (!sameOrigin(req)) return res.status(403).send(pages.messagePage("Not allowed", "Please use the setup page itself."));
    if (!(await setupOpen(req, res, req.body.token))) return;
    const username = typeof req.body.username === "string" ? req.body.username.trim().toLowerCase() : "";
    let error = USERNAME_RE.test(username) ? null : "User name: 1 to 64 characters from a-z, 0-9 and . _ @ + -";
    error = error || auth.checkNewPassword(req.body.password, req.body.password2);
    if (error) {
      return res.status(400).send(pages.setupPage({ token: req.body.token, error, username, min: auth.PASSWORD_MIN, max: auth.PASSWORD_MAX }));
    }
    const password = await auth.hashPassword(req.body.password);
    const created = await store.createUser({ username, password, session_epoch: 1, created_at: new Date(), updated_at: new Date() });
    if (!created) return res.status(404).json({ error: "not found" });
    log(`auth: login created for "${username}" from ${req.clientIp}; the setup page is closed now`);
    sessions.setCookie(res, sessions.issue(store.user.session_epoch));
    res.redirect(303, "/");
  }));

  // Signing out raises the session epoch, which ends every session of the one user.
  app.post("/logout", limit(adminRate), identify, requireSessionPage, requireCsrf, wrap(async (req, res) => {
    await store.updateUser({ updated_at: new Date() }, { session_epoch: 1 });
    sessions.clearCookie(res);
    res.redirect(303, "/login");
  }));

  function requireSessionJson(req, res, next) {
    if (req.auth && req.auth.kind === "session") return next();
    res.status(401).json({ error: "sign in in the browser to change the password" });
  }

  app.post("/account/password", limit(adminRate), identify, requireSessionJson, requireCsrf, wrap(async (req, res) => {
    const wait = failures.waitMs(req.ipKey);
    if (wait) return tooMany(res, Math.ceil(wait / 1000), false);
    const current = typeof req.body.current === "string" ? req.body.current : "";
    failures.fail(req.ipKey);
    const user = await store.refreshUser();
    if (!user || current.length > auth.PASSWORD_MAX || !(await auth.verifyPassword(current, user.password))) {
      return res.status(403).json({ error: "The current password is wrong." });
    }
    failures.success(req.ipKey);
    const error = auth.checkNewPassword(req.body.password, req.body.password2);
    if (error) return res.status(400).json({ error });
    const password = await auth.hashPassword(req.body.password);
    const updated = await store.updateUser({ password, updated_at: new Date() }, { session_epoch: 1 });
    log(`auth: password changed from ${req.clientIp}`);
    sessions.setCookie(res, sessions.issue(updated.session_epoch));
    res.json({ ok: true });
  }));

  // ---- API: the same routes for the admin page (cookie + CSRF token) and for agents (token) --
  const api = express.Router();
  api.use(limit(adminRate), identify, (req, res, next) => {
    if (req.auth) return next();
    res.set("WWW-Authenticate", "Bearer");
    res.status(401).json({ error: "login or API token required" });
  });
  api.use(requireCsrf);
  api.use((req, res, next) => {
    if (store.ready) return next();
    res.set("Retry-After", "5");
    res.status(503).json({ error: "database not reachable yet" });
  });

  const shortUrl = (slug) => `${origin}/${encodeURIComponent(slug)}`;

  api.get("/session", (req, res) => {
    res.json(req.auth.kind === "session" ? { kind: "session", username: req.auth.username, csrf: req.auth.csrf } : { kind: "token" });
  });

  api.get("/links", (req, res) => {
    const links = [...store.links].map(([slug, url]) => ({ slug, url }));
    res.json({ count: links.length, links });
  });

  api.post("/links", wrap(async (req, res) => {
    const target = rules.normalizeTarget(req.body.url, ownHost);
    if (!target.ok) return res.status(400).json({ error: target.error });
    let slug = req.body.slug;
    if (slug === undefined || slug === null || slug === "") {
      let n = store.links.size;
      while (store.links.has(String(n))) n += 1;
      slug = String(n);
    }
    const checked = rules.checkSlug(slug);
    if (!checked.ok) return res.status(400).json({ error: checked.error });
    if (store.links.has(slug)) return res.status(409).json({ error: "slug already exists; change it with PUT", slug });
    if (store.links.size >= rules.MAX_LINKS) return res.status(409).json({ error: `limit of ${rules.MAX_LINKS} links reached` });
    await store.putLink(slug, target.url);
    log(`links: created "${slug}" (${req.auth.kind})`);
    res.status(201).json({ slug, url: target.url, short_url: shortUrl(slug) });
  }));

  function existing(req, res) {
    const slug = req.params.slug;
    if (!store.links.has(slug)) { res.status(404).json({ error: "no such slug" }); return null; }
    if (!rules.SLUG_RE.test(slug) && !rules.isManageableLegacySlug(slug)) {
      res.status(400).json({ error: "this old slug can only be changed in the database" });
      return null;
    }
    return slug;
  }

  api.put("/links/:slug", wrap(async (req, res) => {
    const slug = existing(req, res);
    if (slug === null) return;
    const target = rules.normalizeTarget(req.body.url, ownHost);
    if (!target.ok) return res.status(400).json({ error: target.error });
    await store.putLink(slug, target.url);
    log(`links: changed "${slug}" (${req.auth.kind})`);
    res.json({ slug, url: target.url, short_url: shortUrl(slug) });
  }));

  api.delete("/links/:slug", wrap(async (req, res) => {
    const slug = existing(req, res);
    if (slug === null) return;
    await store.deleteLink(slug);
    log(`links: deleted "${slug}" (${req.auth.kind})`);
    res.json({ deleted: slug });
  }));

  api.use((req, res) => res.status(404).json({ error: "not found" }));
  app.use("/api", api);

  // ---- the public part: following a short link ------------------------------------------------
  app.get("/:slug", limit(redirectRate), (req, res) => {
    if (!store.ready) {
      res.set("Retry-After", "5");
      return res.status(503).json({ error: "starting up, try again in a moment" });
    }
    const target = store.links.get(req.params.slug);
    if (typeof target !== "string" || !/^https?:\/\//i.test(target)) {
      return res.status(404).json({ error: "invalid URL" });
    }
    // As before the login was added: a plain 302 without cache or referrer rules of its own.
    res.removeHeader("Cache-Control");
    res.removeHeader("Referrer-Policy");
    res.redirect(302, target);
  });

  app.use((req, res) => res.status(404).json({ error: "not found" }));

  // No stack traces or internals to clients.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = err && err.status >= 400 && err.status < 500 ? err.status : 500;
    if (status === 500) log(`error: ${err && err.name}${err && err.code ? " " + err.code : ""} on ${req.method} ${req.route ? req.route.path : "?"}`);
    if (res.headersSent) return res.end();
    res.status(status).json({ error: status === 500 ? "internal error" : status === 413 ? "request too large" : "bad request" });
  });

  return app;
}

function configFromEnv(env = process.env) {
  return {
    publicOrigin: (env.PUBLIC_ORIGIN || "https://url.felkru.com").replace(/\/+$/, ""),
    sessionSecret: env.SESSION_SECRET || "",
    apiToken: env.API_TOKEN || "",
    setupToken: env.SETUP_TOKEN || "",
  };
}

module.exports = { createApp, configFromEnv };

if (require.main === module) {
  const { MongoStore } = require("./lib/store");
  const uri = process.env.db_uri || process.env.DB_URI;
  if (!uri) {
    console.error("db_uri is not set");
    process.exit(1);
  }
  const store = new MongoStore(uri);
  const config = configFromEnv();
  const app = createApp({ store, config });
  const port = process.env.PORT || 3000;

  const load = async () => {
    try {
      await store.load();
      console.log(`loaded ${store.links.size} links; login ${store.user ? "exists" : "is not set up yet"}`);
      if (!store.user && config.setupToken.length >= 32) console.log("the one-time setup page is open (needs the setup token)");
    } catch (err) {
      console.error(`database not reachable (${err && err.name}), trying again in 5 s`);
      setTimeout(load, 5000).unref();
    }
  };
  load();

  if (config.sessionSecret.length < 32) console.log("SESSION_SECRET is missing or short: browser login is switched off");
  if (config.apiToken.length < 32) console.log("API_TOKEN is missing or short: the token API is switched off");

  process.on("unhandledRejection", (err) => console.error(`unhandled rejection: ${err && err.name}`));
  const server = app.listen(port, () => console.log(`Listening on port ${port}`));
  for (const signal of ["SIGTERM", "SIGINT"]) {
    process.on(signal, () => {
      server.close(() => store.close().finally(() => process.exit(0)));
      setTimeout(() => process.exit(0), 5000).unref();
    });
  }
}
