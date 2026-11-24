"use strict";
// End-to-end tests against the real Express app with an in-memory store (no database needed).
const test = require("node:test");
const assert = require("node:assert/strict");
const { createApp } = require("../index");
const { MemoryStore } = require("../lib/store");
const rules = require("../lib/validate");
const auth = require("../lib/auth");

const API_TOKEN = "t".repeat(40);
const SETUP_TOKEN = "s".repeat(40);
const PASSWORD = "correct horse battery staple";

async function boot(overrides = {}) {
  const store = new MemoryStore({ blog: "https://example.org/blog", 7: "https://example.org/seven", "straße": "https://example.org/legacy" });
  await store.load();
  const config = { sessionSecret: "k".repeat(40), apiToken: API_TOKEN, setupToken: SETUP_TOKEN, log: () => {}, ...overrides };
  const holder = { config };
  const server = await new Promise((resolve) => {
    // The origin is only known once the port is; createApp reads it at call time.
    const s = require("http").createServer((req, res) => holder.app(req, res));
    s.listen(0, "127.0.0.1", () => resolve(s));
  });
  const origin = `http://localhost:${server.address().port}`;
  holder.app = createApp({ store, config: { ...config, publicOrigin: origin } });
  const call = (path, opts = {}) => fetch(origin + path, { redirect: "manual", ...opts });
  return { store, origin, call, close: () => new Promise((r) => server.close(r)) };
}

const form = (fields) => ({
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(fields).toString(),
});
const bearer = { Authorization: `Bearer ${API_TOKEN}` };
const json = (method, body, headers = {}) => ({ method, headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
const cookieOf = (res) => (res.headers.get("set-cookie") || "").split(";")[0];

async function setUp(t) {
  const res = await t.call("/setup", form({ token: SETUP_TOKEN, username: "felix", password: PASSWORD, password2: PASSWORD }));
  assert.equal(res.status, 303);
  return cookieOf(res);
}

test("redirects stay public, including an old slug outside the new alphabet", async () => {
  const t = await boot();
  try {
    let res = await t.call("/blog");
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), "https://example.org/blog");
    res = await t.call("/7");
    assert.equal(res.headers.get("location"), "https://example.org/seven");
    res = await t.call("/" + encodeURIComponent("straße"));
    assert.equal(res.headers.get("location"), "https://example.org/legacy");
    res = await t.call("/nope");
    assert.equal(res.status, 404);
    for (const name of ["__proto__", "constructor", "toString", "function", "_id"]) {
      assert.equal((await t.call("/" + name)).status, 404, name);
    }
  } finally { await t.close(); }
});

test("nothing can be read or changed without login or token", async () => {
  const t = await boot();
  try {
    assert.equal((await t.call("/api/links")).status, 401);
    assert.equal((await t.call("/api/session")).status, 401);
    assert.equal((await t.call("/api/links", json("POST", { slug: "x", url: "https://example.org" }))).status, 401);
    assert.equal((await t.call("/api/links/blog", json("PUT", { url: "https://evil.example" }))).status, 401);
    assert.equal((await t.call("/api/links/blog", { method: "DELETE" })).status, 401);
    assert.equal((await t.call("/api/links", { headers: { Authorization: "Bearer " + "x".repeat(40) } })).status, 401);
    // the old open routes are gone
    assert.equal((await t.call("/add", form({ key: "blog", url: "https://evil.example" }))).status, 404);
    assert.equal((await t.call("/redirects")).status, 404);
    assert.equal((await t.call("/success")).status, 404);
    const home = await t.call("/");
    assert.equal(home.status, 303);
    assert.equal(home.headers.get("location"), "/login");
    assert.equal((await t.call("/logout", { method: "POST" })).status, 303);
    assert.equal((await t.call("/account/password", json("POST", {}))).status, 401);
    assert.equal(t.store.links.get("blog"), "https://example.org/blog");
  } finally { await t.close(); }
});

test("token API: create, change, delete, list", async () => {
  const t = await boot();
  try {
    let res = await t.call("/api/links", json("POST", { slug: "new-one", url: "example.org/path" }, bearer));
    assert.equal(res.status, 201);
    assert.deepEqual(await res.json(), { slug: "new-one", url: "https://example.org/path", short_url: `${t.origin}/new-one` });
    assert.equal((await t.call("/api/links", json("POST", { slug: "new-one", url: "https://example.org/" }, bearer))).status, 409);
    res = await t.call("/api/links", json("POST", { url: "https://example.org/auto" }, bearer));
    assert.equal(res.status, 201);
    assert.match((await res.json()).slug, /^\d+$/);
    res = await t.call("/api/links/new-one", json("PUT", { url: "https://example.org/changed" }, bearer));
    assert.equal(res.status, 200);
    assert.equal((await t.call("/new-one")).headers.get("location"), "https://example.org/changed");
    res = await t.call("/api/links", { headers: bearer });
    assert.equal((await res.json()).count, 5);
    assert.equal((await t.call("/api/links/new-one", { method: "DELETE", headers: bearer })).status, 200);
    assert.equal((await t.call("/new-one")).status, 404);
    assert.equal((await t.call("/api/links/" + encodeURIComponent("straße"), { method: "DELETE", headers: bearer })).status, 200);
    assert.equal((await t.call("/api/links/nope", { method: "DELETE", headers: bearer })).status, 404);
  } finally { await t.close(); }
});

test("validation: schemes, lengths, slugs", async () => {
  const t = await boot();
  try {
    const bad = [
      { slug: "a", url: "javascript:alert(1)" },
      { slug: "a", url: "JaVaScRiPt:alert(1)" },
      { slug: "a", url: "data:text/html,<script>alert(1)</script>" },
      { slug: "a", url: "file:///etc/passwd" },
      { slug: "a", url: "ftp://example.org/x" },
      { slug: "a", url: "https://user:pw@example.org/" },
      { slug: "a", url: "https://example.org/" + "x".repeat(2100) },
      { slug: "a", url: "https://exa mple.org/" },
      { slug: "a", url: "https://localhost/" },
      { slug: "a", url: "" },
      { slug: "a", url: { $gt: "" } },
      { slug: "a", url: t.origin + "/blog" },
      { slug: "a", url: t.origin.replace("localhost", "localhost.") + "/blog" },
      { slug: "a/b", url: "https://example.org/" },
      { slug: "a.b", url: "https://example.org/" },
      { slug: "$set", url: "https://example.org/" },
      { slug: "x".repeat(65), url: "https://example.org/" },
      { slug: "login", url: "https://example.org/" },
      { slug: "API", url: "https://example.org/" },
      { slug: "function", url: "https://example.org/" },
      { slug: "_id", url: "https://example.org/" },
      { slug: "__proto__", url: "https://example.org/" },
      { slug: { a: 1 }, url: "https://example.org/" },
    ];
    for (const body of bad) {
      const res = await t.call("/api/links", json("POST", body, bearer));
      assert.equal(res.status, 400, JSON.stringify(body).slice(0, 60));
    }
    assert.equal(t.store.links.size, 3);
    const big = await t.call("/api/links", json("POST", { slug: "a", url: "https://example.org/" + "x".repeat(20000) }, bearer));
    assert.equal(big.status, 413);
    const broken = await t.call("/api/links", { method: "POST", headers: { "Content-Type": "application/json", ...bearer }, body: "{not json" });
    assert.equal(broken.status, 400);
    assert.doesNotMatch(await broken.text(), /at |node_modules|SyntaxError/);
    assert.equal(rules.normalizeTarget("example.org:8443/x").url, "https://example.org:8443/x");
    assert.equal(rules.normalizeTarget("  https://example.org/a?b=c#d ").url, "https://example.org/a?b=c#d");
  } finally { await t.close(); }
});

test("setup works once, then login, CSRF, logout", async () => {
  // this test makes more wrong tries than the backoff allows; the backoff has its own tests
  const t = await boot({ failureLimits: { free: 50, globalMax: 100 } });
  try {
    assert.equal((await t.call("/setup")).status, 404);
    assert.equal((await t.call("/setup?token=wrong")).status, 404);
    const page = await t.call("/setup?token=" + SETUP_TOKEN);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /autocomplete="new-password"/);
    let res = await t.call("/setup", form({ token: SETUP_TOKEN, username: "felix", password: "short", password2: "short" }));
    assert.equal(res.status, 400);
    res = await t.call("/setup", form({ token: "wrong", username: "felix", password: PASSWORD, password2: PASSWORD }));
    assert.equal(res.status, 404);
    res = await t.call("/setup", form({ token: SETUP_TOKEN, username: "felix", password: PASSWORD, password2: PASSWORD }));
    assert.equal(res.status, 303);
    const setCookie = res.headers.get("set-cookie");
    assert.match(setCookie, /^__Host-urlsession=/);
    for (const flag of ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"]) assert.ok(setCookie.includes(flag), flag);
    assert.ok(!JSON.stringify(t.store.user).includes(PASSWORD), "password is stored only as a hash");
    assert.equal(t.store.user.password.alg, "scrypt");

    // closed for good
    assert.equal((await t.call("/setup?token=" + SETUP_TOKEN)).status, 404);
    assert.equal((await t.call("/setup", form({ token: SETUP_TOKEN, username: "eve", password: PASSWORD, password2: PASSWORD }))).status, 404);
    assert.equal(t.store.user.username, "felix");

    // wrong password, then the right one
    assert.equal((await t.call("/login", form({ username: "felix", password: "wrong wrong wrong" }))).status, 401);
    assert.equal((await t.call("/login", form({ username: "nobody", password: PASSWORD }))).status, 401);
    res = await t.call("/login", form({ username: "Felix", password: PASSWORD }));
    assert.equal(res.status, 303);
    const cookie = cookieOf(res);

    // a login form posted from another site is refused
    const cross = form({ username: "felix", password: PASSWORD });
    cross.headers.Origin = "https://evil.example";
    assert.equal((await t.call("/login", cross)).status, 403);
    // "Origin: null" (sandboxed frame, or a browser told to hide it): Sec-Fetch-Site decides
    cross.headers.Origin = "null";
    assert.equal((await t.call("/login", cross)).status, 403);
    cross.headers["Sec-Fetch-Site"] = "cross-site";
    assert.equal((await t.call("/login", cross)).status, 403);
    cross.headers["Sec-Fetch-Site"] = "same-origin";
    assert.equal((await t.call("/login", cross)).status, 303);

    assert.equal((await t.call("/", { headers: { Cookie: cookie } })).status, 200);
    const session = await (await t.call("/api/session", { headers: { Cookie: cookie } })).json();
    assert.equal(session.username, "felix");
    assert.equal((await t.call("/api/links", { headers: { Cookie: cookie } })).status, 200);

    // state changes need the CSRF token and our own origin
    const body = { slug: "via-session", url: "https://example.org/s" };
    assert.equal((await t.call("/api/links", json("POST", body, { Cookie: cookie }))).status, 403);
    assert.equal((await t.call("/api/links", json("POST", body, { Cookie: cookie, "X-CSRF-Token": "nope" }))).status, 403);
    assert.equal((await t.call("/api/links", json("POST", body, { Cookie: cookie, "X-CSRF-Token": session.csrf, Origin: "https://evil.example" }))).status, 403);
    assert.equal((await t.call("/api/links", json("POST", body, { Cookie: cookie, "X-CSRF-Token": session.csrf, Origin: t.origin }))).status, 201);
    assert.equal((await t.call("/api/links/via-session", { method: "DELETE", headers: { Cookie: cookie } })).status, 403);
    assert.equal((await t.call("/api/links/via-session", { method: "DELETE", headers: { Cookie: cookie, "X-CSRF-Token": session.csrf } })).status, 200);

    // a forged or altered cookie is no session
    assert.equal((await t.call("/api/links", { headers: { Cookie: cookie.slice(0, -2) + "xx" } })).status, 401);

    // logout without the token does nothing; with it, the old cookie is dead
    assert.equal((await t.call("/logout", { method: "POST", headers: { Cookie: cookie } })).status, 403);
    assert.equal((await t.call("/api/links", { headers: { Cookie: cookie } })).status, 200);
    const out = form({ _csrf: session.csrf });
    out.headers.Cookie = cookie;
    assert.equal((await t.call("/logout", out)).status, 303);
    assert.equal((await t.call("/api/links", { headers: { Cookie: cookie } })).status, 401);
  } finally { await t.close(); }
});

test("password change ends other sessions", async () => {
  const t = await boot();
  try {
    const cookie = await setUp(t);
    const { csrf } = await (await t.call("/api/session", { headers: { Cookie: cookie } })).json();
    const next = "another long password 42";
    let res = await t.call("/account/password", json("POST", { current: "wrong", password: next, password2: next }, { Cookie: cookie, "X-CSRF-Token": csrf }));
    assert.equal(res.status, 403);
    res = await t.call("/account/password", json("POST", { current: PASSWORD, password: next, password2: next }, { Cookie: cookie }));
    assert.equal(res.status, 403);
    res = await t.call("/account/password", json("POST", { current: PASSWORD, password: next, password2: next }, { Cookie: cookie, "X-CSRF-Token": csrf }));
    assert.equal(res.status, 200);
    assert.equal((await t.call("/api/links", { headers: { Cookie: cookie } })).status, 401);
    assert.equal((await t.call("/api/links", { headers: { Cookie: cookieOf(res) } })).status, 200);
    assert.equal((await t.call("/login", form({ username: "felix", password: PASSWORD }))).status, 401);
    assert.equal((await t.call("/login", form({ username: "felix", password: next }))).status, 303);
    // the token cannot change the password
    assert.equal((await t.call("/account/password", json("POST", { current: next, password: PASSWORD, password2: PASSWORD }, bearer))).status, 401);
  } finally { await t.close(); }
});

test("wrong logins are slowed down, also for the right password", async () => {
  const t = await boot();
  try {
    await setUp(t);
    for (let i = 0; i < 5; i++) {
      assert.equal((await t.call("/login", form({ username: "felix", password: "wrong try number " + i }))).status, 401);
    }
    const locked = await t.call("/login", form({ username: "felix", password: PASSWORD }));
    assert.equal(locked.status, 429);
    assert.ok(Number(locked.headers.get("retry-after")) >= 1);
    // the API token is a separate door: the right token keeps working during the password lock,
    // wrong tokens get their own backoff, and even then the right one still works
    assert.equal((await t.call("/api/links", { headers: bearer })).status, 200);
    const wrong = { Authorization: "Bearer " + "w".repeat(40) };
    for (let i = 0; i < 5; i++) assert.equal((await t.call("/api/links", { headers: wrong })).status, 401);
    assert.equal((await t.call("/api/links", { headers: wrong })).status, 429);
    assert.equal((await t.call("/api/links", { headers: bearer })).status, 200);
    // redirects are not affected
    assert.equal((await t.call("/blog")).status, 302);
  } finally { await t.close(); }
});

test("strangers cannot lock the owner out: known addresses skip the cap across addresses", async () => {
  const t = await boot({ failureLimits: { free: 5, globalMax: 6 } });
  try {
    const from = (ip, opts) => ({ ...opts, headers: { ...opts.headers, "X-Forwarded-For": ip } });
    const first = await t.call("/setup", from("198.51.100.1", form({ token: SETUP_TOKEN, username: "felix", password: PASSWORD, password2: PASSWORD })));
    assert.equal(first.status, 303);
    assert.deepEqual(t.store.user.known_addresses, ["198.51.100.1"]);
    for (let i = 0; i < 6; i++) {
      assert.equal((await t.call("/login", from("203.0.113." + (10 + i), form({ username: "felix", password: "guess number " + i })))).status, 401);
    }
    // the cap is reached: a new address is refused even with the right password ...
    assert.equal((await t.call("/login", from("203.0.113.99", form({ username: "felix", password: PASSWORD })))).status, 429);
    // ... the owner's known address is not
    assert.equal((await t.call("/login", from("198.51.100.1", form({ username: "felix", password: PASSWORD })))).status, 303);
    // but a known address still has its own backoff
    for (let i = 0; i < 5; i++) await t.call("/login", from("198.51.100.1", form({ username: "felix", password: "oops " + i })));
    assert.equal((await t.call("/login", from("198.51.100.1", form({ username: "felix", password: PASSWORD })))).status, 429);
  } finally { await t.close(); }
});

test("two creates of the same slug at once: one wins, one gets 409", async () => {
  const t = await boot();
  try {
    const make = (n) => t.call("/api/links", json("POST", { slug: "race", url: "https://example.org/" + n }, bearer));
    const statuses = (await Promise.all([make(1), make(2), make(3)])).map((r) => r.status).sort();
    assert.deepEqual(statuses, [201, 409, 409]);
    const auto = await Promise.all([1, 2, 3].map((n) => t.call("/api/links", json("POST", { url: "https://example.org/auto" + n }, bearer))));
    const slugs = await Promise.all(auto.map((r) => r.json().then((j) => j.slug)));
    assert.equal(new Set(slugs).size, 3);
  } finally { await t.close(); }
});

test("backoff doubles per address and caps across addresses", () => {
  const lim = new auth.FailureLimiter({ free: 3, baseMs: 1000, maxMs: 8000, globalMax: 6, globalWindowMs: 60_000 });
  let now = 1_000_000;
  for (let i = 0; i < 2; i++) lim.fail("a", now);
  assert.equal(lim.waitMs("a", now), 0);
  lim.fail("a", now);
  assert.equal(lim.waitMs("a", now), 1000);
  now += 1000;
  lim.fail("a", now);
  assert.equal(lim.waitMs("a", now), 2000);
  now += 2000;
  lim.fail("a", now);
  assert.equal(lim.waitMs("a", now), 4000);
  assert.equal(lim.waitMs("b", now), 0);
  lim.fail("b", now);
  assert.ok(lim.waitMs("c", now) > 0, "six failures in the window lock every address");
  assert.equal(lim.waitMs("c", now + 61_000), 0);
});

test("headers on pages; plain redirect as before", async () => {
  const t = await boot();
  try {
    const page = await t.call("/login");
    assert.equal(page.status, 200);
    const csp = page.headers.get("content-security-policy");
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.equal(page.headers.get("x-content-type-options"), "nosniff");
    assert.equal(page.headers.get("x-frame-options"), "DENY");
    assert.equal(page.headers.get("referrer-policy"), "same-origin");
    assert.equal(page.headers.get("cache-control"), "no-store");
    assert.equal(page.headers.get("x-powered-by"), null);
    assert.equal(page.headers.get("access-control-allow-origin"), null);
    const html = await page.text();
    assert.doesNotMatch(html, /<script(?! src=)/, "no inline script");
    const redirect = await t.call("/blog");
    assert.equal(redirect.headers.get("referrer-policy"), null);
    assert.equal(redirect.headers.get("x-content-type-options"), "nosniff");
    assert.equal((await t.call("/public/admin.js")).status, 200);
    assert.equal((await t.call("/public/../index.js")).status, 404);
  } finally { await t.close(); }
});

test("without secrets the admin side is closed and redirects still work", async () => {
  const t = await boot({ sessionSecret: "", apiToken: "", setupToken: "" });
  try {
    assert.equal((await t.call("/blog")).status, 302);
    assert.equal((await t.call("/login")).status, 503);
    assert.equal((await t.call("/setup?token=")).status, 404);
    assert.equal((await t.call("/api/links", { headers: { Authorization: "Bearer " } })).status, 401);
    assert.equal((await t.call("/api/links", { headers: { Authorization: "Bearer undefined" } })).status, 401);
  } finally { await t.close(); }
});

test("client address: Cloudflare's header counts only when Cloudflare connected", () => {
  const req = (xff, cf) => ({ headers: { "x-forwarded-for": xff, "cf-connecting-ip": cf }, socket: { remoteAddress: "172.18.0.2" } });
  assert.equal(auth.clientIp(req("162.158.1.1", "203.0.113.9")), "203.0.113.9");
  assert.equal(auth.clientIp(req("198.51.100.7", "203.0.113.9")), "198.51.100.7");
  assert.equal(auth.clientIp(req("1.2.3.4, 198.51.100.7", undefined)), "198.51.100.7");
  assert.equal(auth.clientIp(req(undefined, "203.0.113.9")), "172.18.0.2");
  // reached directly from a public address: forwarded headers are not believed
  const direct = { headers: { "x-forwarded-for": "162.158.1.1", "cf-connecting-ip": "203.0.113.9" }, socket: { remoteAddress: "::ffff:198.51.100.50" } };
  assert.equal(auth.clientIp(direct), "198.51.100.50");
  assert.equal(auth.ipKey("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
  assert.equal(auth.ipKey("2001:db8::1"), "2001:db8:0:0::/64");
});
