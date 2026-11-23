"use strict";
// Password hashing, session cookies, CSRF tokens, failure backoff and client address detection.
// Only Node's built-in crypto is used, so there is nothing extra to install or audit.

const crypto = require("crypto");
const net = require("net");

// ---- password hashing (scrypt) -------------------------------------------------------------
// N=2^15, r=8, p=3 is one of the scrypt settings OWASP lists; it needs about 32 MB per hash.
const SCRYPT = { N: 32768, r: 8, p: 3, keylen: 64 };
const SCRYPT_MAXMEM = 96 * 1024 * 1024;
const PASSWORD_MIN = 12;
const PASSWORD_MAX = 128;

// One hash at a time: a burst of login attempts must not multiply the memory use.
let chain = Promise.resolve();
function serial(fn) {
  const run = chain.then(fn, fn);
  chain = run.catch(() => {});
  return run;
}

function scrypt(password, salt, p) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      Buffer.from(String(password).normalize("NFKC"), "utf8"),
      salt,
      p.keylen,
      { N: p.N, r: p.r, p: p.p, maxmem: SCRYPT_MAXMEM },
      (err, key) => (err ? reject(err) : resolve(key))
    );
  });
}

function hashPassword(password) {
  return serial(async () => {
    const salt = crypto.randomBytes(16);
    const key = await scrypt(password, salt, SCRYPT);
    return { alg: "scrypt", ...SCRYPT, salt: salt.toString("base64"), hash: key.toString("base64") };
  });
}

// Always does the work of one hash, also when there is no user, so timing tells nothing.
function verifyPassword(password, rec) {
  return serial(async () => {
    const usable =
      rec && rec.alg === "scrypt" && typeof rec.salt === "string" && typeof rec.hash === "string" &&
      Number.isInteger(rec.N) && rec.N >= 16384 && rec.N <= 131072 && rec.r === 8 &&
      Number.isInteger(rec.p) && rec.p >= 1 && rec.p <= 8;
    const params = usable ? { N: rec.N, r: rec.r, p: rec.p, keylen: rec.keylen || 64 } : SCRYPT;
    const salt = usable ? Buffer.from(rec.salt, "base64") : Buffer.alloc(16);
    const key = await scrypt(password, salt, params);
    if (!usable) return false;
    const want = Buffer.from(rec.hash, "base64");
    return want.length === key.length && crypto.timingSafeEqual(want, key);
  });
}

function checkNewPassword(pw, pw2) {
  if (typeof pw !== "string" || typeof pw2 !== "string") return "Password is missing.";
  if (pw !== pw2) return "The two passwords are not the same.";
  if (pw.length < PASSWORD_MIN) return `Password needs at least ${PASSWORD_MIN} characters.`;
  if (pw.length > PASSWORD_MAX) return `Password may have at most ${PASSWORD_MAX} characters.`;
  return null;
}

function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ---- sessions ------------------------------------------------------------------------------
// The cookie is "v1.<epoch>.<expiry>.<id>.<hmac>". Nothing is stored per session; the user's
// session epoch (a counter in the database) is part of the cookie, so raising it on logout or
// on a password change ends every session at once.
const COOKIE_NAME = "__Host-urlsession"; // __Host-: Secure, Path=/, no Domain, host-only
const SESSION_TTL_S = 30 * 24 * 3600;

class Sessions {
  constructor(secret) {
    this.enabled = typeof secret === "string" && secret.length >= 32;
    this.key = this.enabled ? crypto.createHash("sha256").update("url-shortener:" + secret).digest() : null;
  }
  mac(text) {
    return crypto.createHmac("sha256", this.key).update(text).digest("base64url");
  }
  issue(epoch) {
    const id = crypto.randomBytes(18).toString("base64url");
    const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_S;
    const payload = `v1.${epoch}.${exp}.${id}`;
    return `${payload}.${this.mac("session:" + payload)}`;
  }
  read(value, epoch) {
    if (!this.enabled || typeof value !== "string" || value.length > 300) return null;
    const parts = value.split(".");
    if (parts.length !== 5 || parts[0] !== "v1") return null;
    const payload = parts.slice(0, 4).join(".");
    if (!safeEqual(parts[4], this.mac("session:" + payload))) return null;
    if (Number(parts[1]) !== epoch) return null;
    if (!(Number(parts[2]) > Date.now() / 1000)) return null;
    return { id: parts[3], csrf: this.mac("csrf:" + parts[3]) };
  }
  setCookie(res, value) {
    res.append("Set-Cookie", `${COOKIE_NAME}=${value}; Path=/; Max-Age=${SESSION_TTL_S}; Secure; HttpOnly; SameSite=Lax`);
  }
  clearCookie(res) {
    res.append("Set-Cookie", `${COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`);
  }
}

function readCookie(req, name) {
  const header = req.headers.cookie;
  if (typeof header !== "string" || header.length > 4096) return null;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

// ---- failure backoff -----------------------------------------------------------------------
// Per address: the first few wrong tries are free, then every further one doubles a lock
// (30 s, 1 min, 2 min ... 15 min). Across all addresses: a cap on wrong tries per 10 minutes,
// which holds even when an attacker changes address for every try.
class FailureLimiter {
  constructor(o = {}) {
    this.free = o.free ?? 5;
    this.baseMs = o.baseMs ?? 30_000;
    this.maxMs = o.maxMs ?? 15 * 60_000;
    this.forgetMs = o.forgetMs ?? 60 * 60_000;
    this.globalMax = o.globalMax ?? 20;
    this.globalWindowMs = o.globalWindowMs ?? 10 * 60_000;
    this.byKey = new Map();
    this.recent = [];
  }
  // Milliseconds the caller has to wait; 0 when a try is allowed.
  waitMs(key, now = Date.now()) {
    while (this.recent.length && this.recent[0] <= now - this.globalWindowMs) this.recent.shift();
    let wait = 0;
    if (this.recent.length >= this.globalMax) wait = this.recent[0] + this.globalWindowMs - now;
    const e = this.byKey.get(key);
    if (e) {
      if (e.last <= now - this.forgetMs) this.byKey.delete(key);
      else if (e.lockedUntil > now) wait = Math.max(wait, e.lockedUntil - now);
    }
    return wait;
  }
  fail(key, now = Date.now()) {
    this.recent.push(now);
    if (this.byKey.size > 20_000) this.prune(now);
    const e = this.byKey.get(key) || { fails: 0, lockedUntil: 0, last: now };
    e.fails += 1;
    e.last = now;
    if (e.fails >= this.free) {
      e.lockedUntil = now + Math.min(this.maxMs, this.baseMs * 2 ** Math.min(e.fails - this.free, 20));
    }
    this.byKey.set(key, e);
  }
  // A try is counted before it is checked; a good one is taken back here.
  success(key) {
    this.byKey.delete(key);
    this.recent.pop();
  }
  prune(now) {
    for (const [k, e] of this.byKey) if (e.lockedUntil <= now && e.last <= now - this.forgetMs) this.byKey.delete(k);
    if (this.byKey.size > 20_000) for (const [k, e] of this.byKey) if (e.lockedUntil <= now) this.byKey.delete(k);
  }
}

// Plain "N requests per window" counter per address.
class RateWindow {
  constructor(limit, windowMs) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.start = Date.now();
    this.counts = new Map();
  }
  // Seconds to wait; 0 when the request is allowed.
  hit(key, now = Date.now()) {
    if (now - this.start >= this.windowMs || this.counts.size > 50_000) {
      this.start = now;
      this.counts.clear();
    }
    const n = (this.counts.get(key) || 0) + 1;
    this.counts.set(key, n);
    return n > this.limit ? Math.max(1, Math.ceil((this.start + this.windowMs - now) / 1000)) : 0;
  }
}

// ---- client address ------------------------------------------------------------------------
// The app sits behind Traefik, which sets X-Forwarded-For to the address that connected to it.
// When that address is one of Cloudflare's, the visitor is in CF-Connecting-IP; from any other
// address that header could be made up, so it is ignored. Source: https://www.cloudflare.com/ips/
const CLOUDFLARE = new net.BlockList();
for (const cidr of [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
  "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
  "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]) {
  const [prefix, bits] = cidr.split("/");
  CLOUDFLARE.addSubnet(prefix, Number(bits), "ipv4");
}
for (const cidr of [
  "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
  "2a06:98c0::/29", "2c0f:f248::/32",
]) {
  const [prefix, bits] = cidr.split("/");
  CLOUDFLARE.addSubnet(prefix, Number(bits), "ipv6");
}

function plainIp(value) {
  let ip = String(value || "").trim();
  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  return net.isIP(ip) ? ip : "";
}

function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  let ip = "";
  if (typeof xff === "string" && xff) ip = plainIp(xff.split(",").pop());
  if (!ip) ip = plainIp(req.socket && req.socket.remoteAddress);
  if (ip && CLOUDFLARE.check(ip, net.isIPv6(ip) ? "ipv6" : "ipv4")) {
    const cf = plainIp(req.headers["cf-connecting-ip"]);
    if (cf) ip = cf;
  }
  return ip || "unknown";
}

// Limiter key: the address, or the /64 for IPv6 (one visitor owns the whole /64).
function ipKey(ip) {
  if (!net.isIPv6(ip)) return ip;
  const [head, tail = ""] = ip.split("::");
  const groups = head.split(":").filter(Boolean);
  if (ip.includes("::")) {
    const rest = tail.split(":").filter(Boolean);
    while (groups.length + rest.length < 8) groups.push("0");
    groups.push(...rest);
  }
  return groups.slice(0, 4).join(":") + "::/64";
}

module.exports = {
  PASSWORD_MIN, PASSWORD_MAX, COOKIE_NAME,
  hashPassword, verifyPassword, checkNewPassword, safeEqual,
  Sessions, readCookie, FailureLimiter, RateWindow, clientIp, ipKey,
};
