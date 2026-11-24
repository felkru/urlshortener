"use strict";
// Input rules for slugs and targets. Everything that reaches the database passes through here.

const SLUG_RE = /^[A-Za-z0-9_-]{1,64}$/;
const URL_MAX = 2048;
const MAX_LINKS = 5000;

// Single-segment paths the app serves itself, fields of the storage document, and names that
// are special on JavaScript objects. A slug may never take one of these.
const RESERVED = new Set([
  "login", "logout", "setup", "account", "admin", "api", "public", "static", "assets",
  "add", "success", "redirects", "healthz", "robots", "favicon",
  "_id", "function", "__proto__", "constructor", "prototype",
]);

function checkSlug(slug) {
  if (typeof slug !== "string") return { ok: false, error: "slug must be text" };
  if (!SLUG_RE.test(slug)) {
    return { ok: false, error: "slug: 1 to 64 characters from A-Z, a-z, 0-9, hyphen and underscore" };
  }
  if (RESERVED.has(slug.toLowerCase())) return { ok: false, error: "slug is reserved by the app" };
  return { ok: true, slug };
}

// Links made before the alphabet rule may hold other characters (one has a German sharp s).
// They keep redirecting, and they may be edited or deleted as long as the name is safe to use
// as a MongoDB field name.
function isManageableLegacySlug(slug) {
  return (
    typeof slug === "string" && slug.length > 0 && slug.length <= 64 &&
    !slug.includes(".") && !slug.startsWith("$") && !/[\u0000-\u001f\u007f]/.test(slug) &&
    !RESERVED.has(slug.toLowerCase())
  );
}

function normalizeTarget(raw, ownHost) {
  if (typeof raw !== "string") return { ok: false, error: "url must be text" };
  let s = raw.trim();
  if (!s) return { ok: false, error: "url is empty" };
  if (s.length > URL_MAX) return { ok: false, error: `url is longer than ${URL_MAX} characters` };
  if (/[\u0000- \u007f]/.test(s)) return { ok: false, error: "url contains spaces or control characters" };

  const m = /^([a-z][a-z0-9+.-]*):(.*)$/i.exec(s);
  if (m) {
    const scheme = m[1].toLowerCase();
    if (scheme === "http" || scheme === "https") {
      if (!m[2].startsWith("//")) return { ok: false, error: "url must start with http:// or https://" };
    } else if (/^\d{1,5}([/?#]|$)/.test(m[2])) {
      s = "https://" + s; // "example.org:8443/x": a host with a port, not a scheme
    } else {
      return { ok: false, error: "only http and https targets are allowed" };
    }
  } else {
    s = "https://" + s;
  }

  let u;
  try {
    u = new URL(s);
  } catch {
    return { ok: false, error: "url is not valid" };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { ok: false, error: "only http and https targets are allowed" };
  }
  if (u.username || u.password) return { ok: false, error: "urls with a user name or password are not allowed" };
  const host = u.hostname;
  if (!host || host.length > 253 || !(host.includes(".") || host.startsWith("["))) {
    return { ok: false, error: "url needs a full host name" };
  }
  const bare = (h) => String(h).toLowerCase().replace(/\.(?=(:\d+)?$)/, ""); // "host." is the same host
  if (ownHost && bare(u.host) === bare(ownHost)) {
    return { ok: false, error: "target points back at the shortener" };
  }
  if (u.href.length > URL_MAX) return { ok: false, error: `url is longer than ${URL_MAX} characters` };
  return { ok: true, url: u.href };
}

module.exports = { SLUG_RE, URL_MAX, MAX_LINKS, RESERVED, checkSlug, isManageableLegacySlug, normalizeTarget };
