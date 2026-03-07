require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { MongoClient } = require("mongodb");
const client = new MongoClient(process.env.db_uri);
const database = client.db("felkrucom");
const dburls = database.collection("short_urls");
const app = express();
let urls = Object.create(null); // no prototype — prevents prototype pollution

// Safe key: alphanumeric, hyphens, underscores only; max 64 chars
const KEY_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const URL_MAX = 2048;

// Block redirects to private/loopback/link-local IP ranges (SSRF prevention)
function isPrivateUrl(urlStr) {
  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch {
    return true; // unparseable — treat as unsafe
  }
  const host = parsed.hostname;
  // IPv4 private/loopback/link-local
  if (/^127\./.test(host)) return true;
  if (/^10\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  if (/^169\.254\./.test(host)) return true;
  if (host === "localhost") return true;
  if (host === "0.0.0.0") return true;
  // IPv6 loopback/link-local
  if (host === "::1") return true;
  if (/^\[?fe80:/i.test(host)) return true;
  return false;
}

async function fetchRedirects() {
  try {
    urls = await dburls.findOne({ function: "sync urls" });
    console.log(urls);
  } catch {
    // Ensures that the client will close when you finish/error
    console.log("error");
  }
}
fetchRedirects();

// Basic Configuration
const port = process.env.PORT || 3000;

app.use(cors(), bodyParser.urlencoded({ extended: false }));

app.use("/public", express.static(`${process.cwd()}/public`));

app.use((req, res, next) => {
  console.log(`Host: ${req.get('host')}`);
  next();
});

app.get("/", function (req, res) {
  if (req.get('host') == "url.felkru.com" || /localhost/.test(req.get('host'))) {
    res.sendFile(process.cwd() + "/views/index.html");
  } else {
    res.redirect(301, 'https://www.felix-krueckel.com/');
  }
});

app.get("/success", function (req, res) {
  res.sendFile(process.cwd() + "/views/success.html");
});

// Your first API endpoint
app.get("/:num", function (req, res) {
  if (!urls[req.params.num]) return res.json({ error: "invalid URL" });
  res.redirect(urls[req.params.num]);
});

app.post("/add", function (req, res) {
  let url = req.body.url;
  let key = req.body.key;

  // Enforce max URL length
  if (!url || url.length > URL_MAX) return res.json({ error: "invalid URL" });

  // Ensure http/https scheme
  if (!url.match(/^(http|https):\/\//)) url = "https://" + url;

  // Basic domain check (must have a dot in host)
  if (!url.match(/.*\..*$/)) return res.json({ error: "invalid URL" });

  // Block private/internal IP ranges to prevent SSRF-as-open-redirect
  if (isPrivateUrl(url)) return res.json({ error: "invalid URL" });

  // Validate or generate a safe key — no prototype/MongoDB-injection risk
  if (key && key !== "") {
    if (!KEY_RE.test(key)) return res.json({ error: "invalid key" });
  } else {
    // Generate a numeric key; skip reserved fields
    key = String(Object.keys(urls).length);
    // Ensure generated key doesn't collide
    while (urls[key] !== undefined) {
      key = String(Number(key) + 1);
    }
  }

  // Reject keys that would collide with known reserved routes
  const RESERVED = ["add", "success", "public"];
  if (RESERVED.includes(key)) return res.json({ error: "invalid key" });

  // When urls already contains this URL, return the existing short url
  const existingKey = Object.keys(urls).find((k) => urls[k] === url);
  if (existingKey !== undefined) {
    return res.json({ original_url: url, short_url: existingKey });
  }

  urls[key] = url;

  // Save urls to database — key is validated; safe to use as field name
  dburls.updateOne(
      { function: "sync urls" },
      {
        $set: {
          [key]: url,
        },
      }
  );

  res.redirect("success" + `?url=${encodeURIComponent(key)}`);
});

app.listen(port, function () {
  console.log(`Listening on port ${port}`);
});
