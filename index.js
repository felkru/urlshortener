require("dotenv").config();
const express = require("express");
const cors = require("cors");
const dns = require("dns");
const bodyParser = require("body-parser");
const { MongoClient } = require("mongodb");
const client = new MongoClient(process.env.db_uri);
const database = client.db("felkrucom");
const dburls = database.collection("short_urls");
const app = express();
let urls = {};

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

app.get("/", function (req, res) {
  res.sendFile(process.cwd() + "/views/index.html");
});

app.get("/redirects", function (req, res) {
  res.json(urls);
});

// Your first API endpoint
app.get("/:num", function (req, res) {
  if (!urls[req.params.num]) return res.json({ error: "invalid URL" });
  res.redirect(urls[req.params.num]);
});

app.post("/add", function (req, res) {
  let url = req.body.url;
  // check if url is valid
  if (!url.match(/^(http|https):\/\//)) url = "https://" + url;
  if (!url.match(/.*\..*$/)) return res.json({ error: "invalid URL" });
  // when urls contains the url, return the short url
  let currentkey = Object.values(urls).indexOf(url);
  if (currentkey > -1) {
    res.json({ original_url: urls[currentkey], short_url: currentkey });
    return;
  }
  urls[Object.keys(urls).length] = url;
  let num = Object.keys(urls).length - 3;
  // save urls to database
  dburls.updateOne(
    { function: "sync urls" },
    {
      $set: {
        [num]: url,
      },
    }
  );
  res.json({ original_url: url, short_url: num });
});

app.listen(port, function () {
  console.log(`Listening on port ${port}`);
});
