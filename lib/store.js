"use strict";
// Storage. The links stay where they always were: one document in felkrucom.short_urls
// ({ function: "sync urls", <slug>: <target>, ... }), so nothing had to be migrated.
// The login (one user) lives next to it in felkrucom.shortener_auth as { _id: "user", ... }.

const META_FIELDS = new Set(["_id", "function"]);
const LINKS_FILTER = { function: "sync urls" };

class MongoStore {
  constructor(uri) {
    const { MongoClient } = require("mongodb");
    this.client = new MongoClient(uri, { serverSelectionTimeoutMS: 10_000 });
    const db = this.client.db("felkrucom");
    this.linksCol = db.collection("short_urls");
    this.authCol = db.collection("shortener_auth");
    this.links = new Map();
    this.user = null;
    this.ready = false;
  }

  // Loads links and user. Redirects answer 503 until this has worked once, so a database
  // that is briefly away at start never looks like "no links".
  async load() {
    const doc = await this.linksCol.findOne(LINKS_FILTER);
    const links = new Map();
    for (const [key, value] of Object.entries(doc || {})) {
      if (!META_FIELDS.has(key) && typeof value === "string") links.set(key, value);
    }
    this.user = await this.authCol.findOne({ _id: "user" });
    this.links = links;
    this.ready = true;
  }

  async putLink(slug, url) {
    await this.linksCol.updateOne(LINKS_FILTER, { $set: { [slug]: url } }, { upsert: true });
    this.links.set(slug, url);
  }

  async deleteLink(slug) {
    await this.linksCol.updateOne(LINKS_FILTER, { $unset: { [slug]: "" } });
    this.links.delete(slug);
  }

  async refreshUser() {
    this.user = await this.authCol.findOne({ _id: "user" });
    return this.user;
  }

  // False when a user already exists: the fixed _id makes "only once" atomic.
  async createUser(fields) {
    try {
      await this.authCol.insertOne({ _id: "user", ...fields });
    } catch (err) {
      if (err && err.code === 11000) return false;
      throw err;
    }
    await this.refreshUser();
    return true;
  }

  async updateUser(set, inc) {
    const update = { $set: set };
    if (inc) update.$inc = inc;
    await this.authCol.updateOne({ _id: "user" }, update);
    return this.refreshUser();
  }

  async deleteUser() {
    await this.authCol.deleteOne({ _id: "user" });
    this.user = null;
  }

  async close() {
    await this.client.close();
  }
}

// Same interface without a database, for the tests.
class MemoryStore {
  constructor(initial = {}) {
    this.links = new Map(Object.entries(initial));
    this.user = null;
    this.ready = false;
  }
  async load() {
    this.ready = true;
  }
  async putLink(slug, url) {
    this.links.set(slug, url);
  }
  async deleteLink(slug) {
    this.links.delete(slug);
  }
  async refreshUser() {
    return this.user;
  }
  async createUser(fields) {
    if (this.user) return false;
    this.user = { _id: "user", ...fields };
    return true;
  }
  async updateUser(set, inc) {
    Object.assign(this.user, set);
    for (const [k, v] of Object.entries(inc || {})) this.user[k] = (this.user[k] || 0) + v;
    return this.user;
  }
  async deleteUser() {
    this.user = null;
  }
  async close() {}
}

module.exports = { MongoStore, MemoryStore };
