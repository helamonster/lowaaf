#!/usr/bin/env node
// Registers a Vaultwarden account with keys that the Bitwarden SDK can decrypt.
//
// Key insight: the Bitwarden SDK (bitwarden-crypto Rust crate) calls
// Hkdf::from_prk(master_key) — using the PBKDF2 master key directly as the
// HKDF PRK (skip extract). Node.js crypto.hkdfSync() always runs the full
// extract+expand, producing different keys. So we implement expand-only here.
//
// Used by bw_test_live.sh; also callable standalone:
//   BW_EMAIL=x BW_PASSWORD=y BW_SERVER=https://... node docker/register.js

const crypto = require('crypto');
const https  = require('https');

const EMAIL      = process.env.BW_EMAIL    || 'waftest@example.com';
const PASSWORD   = process.env.BW_PASSWORD || 'WafTest1234!';
const SERVER     = process.env.BW_SERVER   || 'https://localhost:8443';
const ITERATIONS = 600000;

function hkdfExpand(prk, info, len) {
  const infoBytes = Buffer.from(info);
  let t = Buffer.alloc(0);
  let okm = Buffer.alloc(0);
  for (let i = 1; okm.length < len; i++) {
    t = crypto.createHmac('sha256', prk)
              .update(Buffer.concat([t, infoBytes, Buffer.from([i])]))
              .digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.slice(0, len);
}

function encrypt(plaintext, encKey, macKey) {
  const iv  = crypto.randomBytes(16);
  const c   = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  const ct  = Buffer.concat([c.update(plaintext), c.final()]);
  const mac = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  return '2.' + iv.toString('base64') + '|' + ct.toString('base64') + '|' + mac.toString('base64');
}

function post(url, body) {
  return new Promise((resolve, reject) => {
    const u   = new URL(url);
    const raw = JSON.stringify(body);
    const req = https.request({
      hostname: u.hostname, port: u.port || 443, path: u.pathname,
      method: 'POST', rejectUnauthorized: false,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(raw) },
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    req.on('error', reject);
    req.write(raw); req.end();
  });
}

(async () => {
  const masterKey          = crypto.pbkdf2Sync(PASSWORD, EMAIL.toLowerCase(), ITERATIONS, 32, 'sha256');
  const encKey             = hkdfExpand(masterKey, 'enc', 32);
  const macKey             = hkdfExpand(masterKey, 'mac', 32);
  const masterPasswordHash = crypto.pbkdf2Sync(masterKey, PASSWORD, 1, 32, 'sha256').toString('base64');
  const symKey             = crypto.randomBytes(64);
  const protectedSymKey    = encrypt(symKey, encKey, macKey);

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength:      2048,
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  const res = await post(SERVER + '/identity/accounts/register', {
    email: EMAIL, masterPasswordHash, masterPasswordHint: '', name: 'WAF Test',
    kdf: 0, kdfIterations: ITERATIONS, key: protectedSymKey,
    keys: {
      encryptedPrivateKey: encrypt(privateKey, symKey.slice(0, 32), symKey.slice(32, 64)),
      publicKey:           publicKey.toString('base64'),
    },
  });

  if (res.status === 200) {
    process.exit(0);
  } else {
    process.stderr.write('Registration failed: HTTP ' + res.status + ' ' + res.body + '\n');
    process.exit(1);
  }
})();
