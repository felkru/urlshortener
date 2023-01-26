require("dotenv").config();
const express = require("express");
const cors = require("cors");
const dns = require("dns");
const bodyParser = require("body-parser");
const app = express();
let urls = {};

// Basic Configuration
const port = process.env.PORT || 3000;

app.use(cors(), bodyParser.urlencoded({ extended: false }));

app.use("/public", express.static(`${process.cwd()}/public`));

app.get("/", function (req, res) {
  res.sendFile(process.cwd() + "/views/index.html");
});

// Your first API endpoint
app.get("/api/shorturl/:num", function (req, res) {
  if (!urls[req.params.num]) return res.json({ error: "invalid URL" });
  res.redirect(urls[req.params.num]);
});

app.post("/api/shorturl/", function (req, res) {
  let url = req.body.url;
  // check if url is valid
  if (!url.match(/^(http|https):\/\/.*\..*$/))
    return res.json({ error: "invalid URL" });
  // if (!url.match(/^(http|https):\/\//)) url = "https://" + url;
  // when urls contains the url, return the short url
  let currentkey = Object.values(urls).indexOf(url);
  if (currentkey > -1) {
    res.json({ original_url: urls[currentkey], short_url: currentkey });
    return;
  }
  urls[Object.keys(urls).length] = url;
  let num = Object.keys(urls).length - 1;
  res.json({ original_url: url, short_url: num });
});

app.listen(port, function () {
  console.log(`Listening on port ${port}`);
});
