// Deliberately vulnerable Express app used to demo CodeCheck. DO NOT deploy.
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const serialize = require('node-serialize');
const { exec, execFile } = require('child_process');
const mysql = require('mysql');

const app = express();
const db = mysql.createConnection({ host: 'db', user: 'root', password: 'hunter2-prod' }); // CS004
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret';       // CS004 hardcoded fallback

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id = ' + id, (err, rows) => res.json(rows)); // CS002 tainted
});

app.get('/user-safe', (req, res) => {
  db.query('SELECT * FROM users WHERE id = ?', [req.query.id], (err, rows) => res.json(rows)); // safe
});

app.get('/user-int', (req, res) => {
  const id = parseInt(req.query.id, 10);
  db.query(`SELECT * FROM users WHERE id = ${id}`, (err, rows) => res.json(rows)); // sanitized: parseInt
});

app.get('/ping', (req, res) => {
  exec(`ping -c1 ${req.query.host}`, (e, out) => res.send(out));           // CS003 tainted
  execFile('ping', ['-c1', 'localhost'], () => {});                        // safe: fixed argv
});

app.get('/calc', (req, res) => {
  res.json({ result: eval(req.query.expr) });                              // CS001 tainted
});

app.get('/hello', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');                       // CS011 reflected XSS
});

app.get('/hello-safe', (req, res) => {
  res.render('hello', { name: req.query.name });                           // safe: auto-escaped
});

app.get('/file', (req, res) => {
  const p = path.join(__dirname, 'files', req.query.f);
  fs.readFile(p, 'utf8', (err, data) => res.send(data));                   // CS009 traversal
});

app.get('/download', (req, res) => {
  res.sendFile(path.basename(req.query.f), { root: '/srv/files' });        // safe: basename + root
  res.download(req.query.f);                                               // CS009 traversal
});

app.get('/fetch', async (req, res) => {
  const r = await axios.get(req.query.url);                                // CS012 SSRF
  const agent = new https.Agent({ rejectUnauthorized: false });            // CS007
  res.json(r.data);
});

app.post('/load', (req, res) => {
  const obj = serialize.unserialize(req.body.data);                        // CS006 tainted
  res.json(obj);
});

app.get('/token', (req, res) => {
  const sessionToken = Math.random().toString(36).slice(2);                // CS010
  const signed = jwt.sign({ u: 1 }, 'my-jwt-secret');                      // CS004
  res.json({ sessionToken, signed });
});

function fingerprint(data) {
  return crypto.createHash('md5').update(data).digest('hex');              // CS005
}
function checksum(data) {
  return crypto.createHash('md5').update(data).digest('hex'); // nosec - non-security checksum
}

// ---- browser-side code
const q = new URLSearchParams(location.search).get('q');
document.getElementById('out').innerHTML = q;                              // CS011 DOM XSS
document.getElementById('safe').textContent = q;                           // safe
const el = <div dangerouslySetInnerHTML={{ __html: location.hash }} />;    // CS011 (JSX)
setTimeout("refresh('" + location.hash + "')", 100);                       // CS001 string timer
setTimeout(() => refresh(), 100);                                          // safe: function

app.listen(3000);
