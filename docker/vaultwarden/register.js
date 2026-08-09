#!/usr/bin/env node
// Registers a Vaultwarden account with keys that the Bitwarden SDK can decrypt.
//
// Key insight: the Bitwarden SDK (bitwarden-crypto Rust crate) calls
// Hkdf::from_prk(master_key) — using the PBKDF2 master key directly as the
// HKDF PRK (skip extract). Node.js crypto.hkdfSync() always runs the full
// extract+expand, producing different keys. So we implement expand-only here.
//
// Used by bw_test_live.sh (registration only - strict, exits non-zero on any
// registration failure since that script always wipes the VW volume first,
// so a failure there is always real) and test/runner.lua's vaultwarden login
// dispatch (registration + login, BW_TOLERATE_EXISTING=1 - runner.lua may
// run repeatedly against a stack that already has the test account
// registered from a previous run, so "already registered" there is expected,
// not an error). Also callable standalone:
//   BW_EMAIL=x BW_PASSWORD=y BW_SERVER=https://... node docker/vaultwarden/register.js
//
// With BW_TOLERATE_EXISTING=1, prints the login access_token as the last
// line of stdout (silent otherwise, matching the original standalone
// register-only contract bw_test_live.sh depends on).

const crypto = require('crypto');
const http   = require('http');
const https  = require('https');

const EMAIL              = process.env.BW_EMAIL    || 'waftest@example.com';
const PASSWORD           = process.env.BW_PASSWORD || 'WafTest1234!';
const SERVER             = process.env.BW_SERVER   || 'https://localhost:8443';
const TOLERATE_EXISTING  = process.env.BW_TOLERATE_EXISTING === '1';
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

// `raw` is a pre-encoded body string (JSON or form) - runner.lua's login
// dispatch needs both a JSON body (register) and a form body (token), and
// SERVER may be plain HTTP (online-test-full's default vaultwarden port,
// 8888) or HTTPS (bw_test_live.sh's 8443) - both need to go through
// whichever transport the caller's URL actually names.
function post(url, raw, contentType) {
  return new Promise((resolve, reject) => {
    const u         = new URL(url);
    const transport = u.protocol === 'https:' ? https : http;
    const opts = {
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname, method: 'POST',
      headers: { 'Content-Type': contentType, 'Content-Length': Buffer.byteLength(raw) },
    };
    if (u.protocol === 'https:') opts.rejectUnauthorized = false;
    const req = transport.request(opts, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    req.on('error', reject);
    req.write(raw); req.end();
  });
}

function postJson(url, body) {
  return post(url, JSON.stringify(body), 'application/json');
}

function postForm(url, fields) {
  const raw = Object.entries(fields)
    .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v))
    .join('&');
  return post(url, raw, 'application/x-www-form-urlencoded');
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

  const res = await postJson(SERVER + '/identity/accounts/register', {
    email: EMAIL, masterPasswordHash, masterPasswordHint: '', name: 'WAF Test',
    kdf: 0, kdfIterations: ITERATIONS, key: protectedSymKey,
    keys: {
      encryptedPrivateKey: encrypt(privateKey, symKey.slice(0, 32), symKey.slice(32, 64)),
      publicKey:           publicKey.toString('base64'),
    },
  });

  if (res.status === 200) {
    // ok
  } else if (TOLERATE_EXISTING) {
    process.stderr.write('Registration returned HTTP ' + res.status +
      ' (continuing - assumed already registered from a prior run): ' + res.body + '\n');
  } else {
    process.stderr.write('Registration failed: HTTP ' + res.status + ' ' + res.body + '\n');
    process.exit(1);
  }

  if (!TOLERATE_EXISTING) process.exit(0);

  // Real login (matches vaultwarden.lua's "login" route form schema:
  // grant_type/username/password/scope/client_id/deviceType/
  // deviceIdentifier/deviceName), through whichever base SERVER names - for
  // test/runner.lua that's the WAF-fronted port, so this is real traffic the
  // WAF should see, not a direct-to-backend bypass.
  const tokenRes = await postForm(SERVER + '/identity/connect/token', {
    grant_type:       'password',
    username:         EMAIL,
    password:         masterPasswordHash,
    scope:            'api offline_access',
    client_id:        'cli',
    deviceType:       '21',                 // Bitwarden CLI's own DeviceType enum value
    deviceIdentifier: crypto.randomUUID(),
    deviceName:       'waf-test',
  });

  if (tokenRes.status !== 200) {
    process.stderr.write('Login failed: HTTP ' + tokenRes.status + ' ' + tokenRes.body + '\n');
    process.exit(1);
  }

  let token;
  try {
    token = JSON.parse(tokenRes.body).access_token;
  } catch (e) {
    process.stderr.write('Login response was not valid JSON: ' + tokenRes.body + '\n');
    process.exit(1);
  }
  if (!token) {
    process.stderr.write('Login response had no access_token: ' + tokenRes.body + '\n');
    process.exit(1);
  }

  process.stdout.write(token + '\n');
  process.exit(0);
})();
