"use strict";
// Removes the login so the one-time setup page works again (it still needs SETUP_TOKEN).
// Use when the password is lost. Run inside the container:
//   docker compose -p my_vps exec url-shortener node scripts/reset-login.js --yes
// The links are not touched. Every browser session ends.
const { MongoStore } = require("../lib/store");

(async () => {
  if (!process.argv.includes("--yes")) {
    console.error("This deletes the shortener's login. Run again with --yes to do it.");
    process.exit(2);
  }
  const uri = process.env.db_uri || process.env.DB_URI;
  if (!uri) {
    console.error("db_uri is not set");
    process.exit(1);
  }
  const store = new MongoStore(uri);
  try {
    await store.deleteUser();
    console.log("Login removed. Set SETUP_TOKEN, restart the service and open /setup?token=<SETUP_TOKEN>.");
  } catch (err) {
    console.error(`failed: ${err && err.name}`);
    process.exitCode = 1;
  } finally {
    await store.close();
  }
})();
