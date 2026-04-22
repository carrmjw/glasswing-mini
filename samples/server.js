// samples/server.js — intentionally vulnerable code for smoke-testing glasswing.
// DO NOT RUN IN PRODUCTION. Every "bug" here is planted.

import express from "express";
import { exec } from "node:child_process";
import fetch from "node-fetch";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const app = express();
app.use(express.json());

// BUG 1: RCE via unsanitized exec (attacker-controlled `host`)
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    res.send(stdout);
  });
});

// BUG 2: SSRF — server follows any URL the user passes, including internal AWS metadata.
app.get("/fetch-url", async (req, res) => {
  const url = req.query.url;
  const r = await fetch(url);
  const text = await r.text();
  res.send(text);
});

// BUG 3: Path traversal — no normalization, attacker can read /etc/passwd via ?name=../../../etc/passwd
app.get("/doc", async (req, res) => {
  const name = req.query.name;
  const path = join("/var/docs", name);
  const content = await readFile(path, "utf8");
  res.send(content);
});

// BUG 4: SQLi via string concatenation (imaginary pg client)
import pg from "pg";
const pool = new pg.Pool();
app.get("/user", async (req, res) => {
  const id = req.query.id;
  const result = await pool.query(`SELECT * FROM users WHERE id = ${id}`);
  res.json(result.rows);
});

// CLEAN: parameterized query — should NOT be flagged
app.get("/user-safe", async (req, res) => {
  const id = req.query.id;
  const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
  res.json(result.rows);
});

// BUG 5: Auth bypass — admin check is a string comparison against a user-controlled header
app.post("/admin/delete", (req, res) => {
  if (req.headers["x-role"] === "admin") {
    // proceed with delete
    res.send("deleted");
  } else {
    res.status(403).send("nope");
  }
});

app.listen(3000);
