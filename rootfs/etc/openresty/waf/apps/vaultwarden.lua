-- --------------------------------------------------------------------------------------
-- 
-- Lua OpenResty Web Application and API Firewall (LOWAAF)
--
-- Concept, Framework and Application Firewall Implementation by:
-- Jeremy Bryan Smith <helamonster@gmail.com>
-- <https://jeremybryansmith.com>
--
-- With assistance from: Claude Sonnet 4.6 <noreply@anthropic.com> 
--
-- --------------------------------------------------------------------------------------
--
-- vaultwarden.lua : LOWAFF for VaultWarden
--
-- VaultWarden: The Unofficial Bitwarden compatible server written in Rust
-- <https://github.com/dani-garcia/vaultwarden>
-- <https://www.vaultwarden.net/>
--
-- --------------------------------------------------------------------------------------




local T = require "waf.types"

-- ---------------------------------------------------------------------------
-- Bitwarden client User-Agent validators (Vaultwarden-specific)
-- ---------------------------------------------------------------------------

-- Web vault and browser extensions use the browser's native UA.
local function ua_web()
  return T.string({
    max       = 512,
    match     = [[(?i)Mozilla/5\.0]],
    not_match = [[(?i)Electron/]],   -- Electron UA also starts with Mozilla/5.0
  })
end

-- iOS and Android mobile apps: "Bitwarden_Mobile/YYYY.M.P (...)"
local function ua_mobile()
  return T.string({ max = 512, match = [[(?i)^Bitwarden_Mobile/]] })
end

-- Electron desktop app: "... bitwarden/YYYY.M.P ... Electron/N ..."
local function ua_desktop()
  return T.string({ max = 512, match = [[(?i)bitwarden/[0-9].*Electron/]] })
end

-- Official CLI: "Bitwarden_CLI/YYYY.M.P (PLATFORM)"
local function ua_cli()
  return T.string({ max = 512, match = [[(?i)^bitwarden_cli/]] })
end

-- Accepts any official Bitwarden client (web, mobile, desktop, CLI).
local function ua_any_known()
  local clients = { ua_web(), ua_mobile(), ua_desktop(), ua_cli() }
  return function(v, path)
    if type(v) ~= "string" then return false, path .. " must be a string" end
    if #v > 512 then return false, path .. " too long" end
    for _, check in ipairs(clients) do
      if check(v, path) then return true end
    end
    return false, path .. ": unrecognized Bitwarden client user-agent"
  end
end

-- ---------------------------------------------------------------------------
-- shared type aliases
-- ---------------------------------------------------------------------------
local enc     = T.string({ max = 10000 })       -- Bitwarden-encrypted ciphertext blob
local sml     = T.string({ max = 256 })
local med     = T.string({ max = 2048 })
local nu_enc  = T.nullable(enc)
local nu_uuid = T.nullable(T.uuid())
local nu_bool = T.nullable(T.boolean())
local nu_num  = T.nullable(T.number({ integer = true }))
local nu_sml  = T.nullable(sml)

-- UUID regex fragment reused in path patterns
local U = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

-- attachment/send file IDs: arbitrary base64url up to 64 chars
local FILEID = "[a-zA-Z0-9_-]{1,64}"

-- ---------------------------------------------------------------------------
-- JSON schemas for high-value endpoints
-- ---------------------------------------------------------------------------
local cipher_uri = T.object({
  uri         = nu_enc,
  match       = T.nullable(T.number({ integer = true, min = 0, max = 5 })),
  uriChecksum = nu_enc,
  response    = nu_enc,
})

local cipher_field = T.object({
  type     = T.nullable(T.number({ integer = true, min = 0, max = 3 })),
  name     = nu_enc,
  value    = nu_enc,
  linkedId = nu_num,
  response = nu_enc,
})

local cipher_body = T.object({
  type            = T.number({ integer = true, min = 1, max = 4 }),
  name            = enc,
  notes           = nu_enc,
  favorite        = nu_bool,
  folderId        = nu_uuid,
  organizationId  = nu_uuid,
  collectionIds   = T.nullable(T.array(T.uuid(), { max = 200 })),
  key                   = nu_enc,
  encryptedFor          = nu_enc,
  lastKnownRevisionDate = T.nullable(T.iso8601()),
  -- deprecated: id → encrypted filename; superseded by attachments2
  attachments  = T.nullable(T.dict(enc)),
  attachments2 = T.nullable(T.dict(T.object({
    fileName              = nu_enc,
    key                   = nu_enc,
    fileSize              = nu_num,
    adminRequest          = nu_bool,
    lastKnownRevisionDate = T.nullable(T.iso8601()),
  }))),
  reprompt        = T.nullable(T.number({ integer = true, min = 0, max = 1 })),
  fields          = T.nullable(T.array(cipher_field, { max = 100 })),
  passwordHistory = T.nullable(T.array(T.object({
    lastUsedDate = T.string({ max = 64 }),
    password     = enc,
  }), { max = 200 })),
  login = T.nullable(T.object({
    username             = nu_enc,
    password             = nu_enc,
    totp                 = nu_enc,
    uris                 = T.nullable(T.array(cipher_uri, { max = 100 })),
    passwordRevisionDate = T.nullable(T.iso8601()),
    response             = nu_enc,
  })),
  card = T.nullable(T.object({
    cardholderName = nu_enc,
    brand          = nu_enc,
    number         = nu_enc,
    expMonth       = nu_enc,
    expYear        = nu_enc,
    code           = nu_enc,
    response       = nu_enc,
  })),
  identity = T.nullable(T.object({
    title          = nu_enc,
    firstName      = nu_enc,
    middleName     = nu_enc,
    lastName       = nu_enc,
    address1       = nu_enc,
    address2       = nu_enc,
    address3       = nu_enc,
    city           = nu_enc,
    state          = nu_enc,
    postalCode     = nu_enc,
    country        = nu_enc,
    company        = nu_enc,
    email          = nu_enc,
    phone          = nu_enc,
    ssn            = nu_enc,
    username       = nu_enc,
    passportNumber = nu_enc,
    licenseNumber  = nu_enc,
    response       = nu_enc,
  })),
  secureNote = T.nullable(T.object({
    type     = T.number({ integer = true, min = 0, max = 0 }),
    response = nu_enc,
  })),
})

-- ---------------------------------------------------------------------------
-- Shared body for bulk cipher operations: archive, unarchive, bulk-delete
-- (src/api/core/ciphers.rs: CipherIdsData)
-- ---------------------------------------------------------------------------
local cipher_ids_body = T.object({
  ids = T.array(T.uuid(), { max = 2000 }),
})

-- ---------------------------------------------------------------------------
-- Attachment upload initiation (v2)
-- (src/api/core/ciphers.rs: AttachmentRequestData)
-- Returns a pre-signed upload URL; the actual file goes directly to that URL.
-- fileSize is NumberOrString in Rust but Bitwarden clients send it as a number.
-- ---------------------------------------------------------------------------
local attachment_init_body = T.object({
  key          = enc,
  fileName     = enc,
  fileSize     = T.number({ integer=true, min=0, max=536870912 }),  -- 512 MB ceiling
  adminRequest = nu_bool,
})

-- ---------------------------------------------------------------------------
-- Send body: shared by send-create (POST /api/sends) and
-- send-create-file (POST /api/sends/file/v2)
-- (src/api/core/sends.rs: SendData)
-- ---------------------------------------------------------------------------
local send_body = T.object({
  type           = T.number({ integer=true, min=0, max=1 }),  -- 0=text, 1=file
  key            = enc,
  name           = enc,
  deletionDate   = T.iso8601(),
  disabled       = T.boolean(),
  password       = nu_enc,
  maxAccessCount = T.nullable(T.number({ integer=true, min=0, max=1000000 })),
  expirationDate = T.nullable(T.iso8601()),
  hideEmail      = nu_bool,
  notes          = nu_enc,
  fileLength     = T.nullable(T.number({ integer=true, min=0, max=536870912 })),
  id             = nu_uuid,
  text = T.nullable(T.object({
    text   = nu_enc,
    hidden = nu_bool,
  })),
  file = T.nullable(T.object({
    fileName = nu_enc,
    id       = nu_uuid,
    size     = T.nullable(T.string({ max=32 })),
    sizeName = T.nullable(T.string({ max=32 })),
  })),
})

-- ---------------------------------------------------------------------------
-- JWT claims schema for the Vaultwarden login token (LoginJwtClaims in auth.rs)
-- Used on the /notifications/hub?access_token=... WebSocket endpoint.
-- Signature verification is Vaultwarden's job; we validate structure only.
-- ---------------------------------------------------------------------------
local vw_access_token = T.jwt_claims({
  nbf            = T.number({ integer=true }),
  exp            = T.number({ integer=true }),
  -- iss = "https://<host>|login" — the pipe+login suffix is Vaultwarden-specific
  iss            = T.string({ max=256, match=[[^https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+\|login$]] }),
  sub            = T.uuid(),
  premium        = T.boolean(),
  name           = T.string({ max=256 }),
  email          = T.email(),
  email_verified = T.boolean(),
  sstamp         = T.uuid(),
  device         = T.uuid(),
  devicetype     = T.string({ max=32 }),  -- human-readable DeviceType name
  client_id      = T.string({ max=16, enum={
    ["browser"] = true,
    ["web"]     = true,
    ["desktop"] = true,
    ["mobile"]  = true,
    ["cli"]     = true,
  }}),
  scope = T.array(T.string({ max=32, enum={
    ["api"]            = true,
    ["offline_access"] = true,
  }}), { max=5 }),
  amr   = T.array(T.string({ max=64 }), { max=10 }),
}, {
  -- JWT header: {"typ":"JWT","alg":"RS256"}
  typ = T.string({ enum={ ["JWT"]=true } }),
  alg = T.string({ enum={ ["RS256"]=true } }),
})

-- ---------------------------------------------------------------------------
return {
  name    = "vaultwarden",
  mode    = "log",   -- flip to "block" after validating against real traffic
  verbose = 2,

  defaults = {
    max_body = 5 * 1024 * 1024,  -- 5 MB; covers attachment uploads
    allowed_methods = {
      GET = true, POST = true, PUT = true, DELETE = true, OPTIONS = true,
    },

    -- Enforce a header name whitelist on every route.
    -- If running behind a reverse proxy, add T.common_proxy_headers():
    --   allowed_headers = T.merge_headers(T.common_request_headers(), T.common_proxy_headers()),
    allowed_headers = T.merge_headers(T.common_request_headers(), {
      "bitwarden-client-name",
      "bitwarden-client-version",
      "bitwarden-package-type",
      "device-type",
      "device-identifier",
      "is-prerelease",
    }),

    -- Validate header values on every route.
    headers = {
      -- ua_any_known() permits all official Bitwarden clients (web, mobile, desktop, CLI).
      -- To restrict to a subset, replace with one or more of:
      --   ua_web()      -- browser extensions only
      --   ua_mobile()   -- iOS / Android app
      --   ua_desktop()  -- Electron desktop app
      --   ua_cli()      -- bitwarden-cli
      ["User-Agent"] = ua_any_known(),
      ["priority"]   = T.http_priority(),
      ["sec-gpc"]    = T.sec_gpc(),
      -- DeviceType enum (libs/common/src/enums/device-type.enum.ts): 0–26
      ["device-type"]            = T.string({ max=2,  match=[[^(?:[0-9]|1[0-9]|2[0-6])$]] }),
      -- Version string: YYYY.M.P  (e.g. 2026.5.1)
      ["bitwarden-client-version"] = T.string({ max=32, match=[[^\d{4}\.\d{1,2}\.\d+$]] }),
      -- Only sent as "1" on prerelease builds; absent on stable
      ["is-prerelease"]          = T.string({ max=1,  enum={ ["1"]=true } }),
      -- Device GUID sent by all official clients to identify the registered device
      ["device-identifier"]      = T.uuid(),
      ["bitwarden-package-type"] = T.string({ max=32, enum={
        ["Chrome Extension"]         = true,
        ["Firefox Extension"]        = true,
        ["Opera Extension"]          = true,
        ["Edge Extension"]           = true,
        ["Vivaldi Extension"]        = true,
        ["Safari Extension"]         = true,
        ["Unknown Browser Extension"]= true,
      }}),
    },
  },

  routes = {

    -- AUTHENTICATION --------------------------------------------------------

    {
      name         = "login",
      method       = "POST",
      path         = [[^/identity/connect/token$]],
      content_type = "application/x-www-form-urlencoded",
      form = T.object({
        grant_type        = T.string({ enum = { password = true, refresh_token = true, client_credentials = true } }),
        username          = T.nullable(T.email()),
        password          = T.nullable(med),
        scope             = nu_sml,
        client_id         = nu_sml,
        client_secret     = nu_sml,
        refresh_token     = T.nullable(med),
        -- form-encoded: values arrive as strings, not numbers
        deviceType        = T.nullable(T.string({ max=2, match=[[^(?:[0-9]|[12][0-9]|30)$]] })),
        deviceIdentifier  = nu_sml,
        deviceName        = nu_sml,
        devicePushToken   = nu_sml,
        twoFactorToken    = nu_sml,
        twoFactorProvider = T.nullable(T.string({ max=2, match=[[^(?:[0-9]|10)$]] })),
        twoFactorRemember = T.nullable(T.string({ max=1, match=[[^[01]$]] })),
        captchaResponse   = nu_sml,
        authRequest       = T.nullable(T.string({ max = 512 })),
      }),
    },

    {
      name         = "prelogin",
      method       = "POST",
      paths        = { [[^/identity/accounts/prelogin$]], [[^/identity/accounts/prelogin/password$]] },
      content_type = "application/json",
      json = T.object({ email = T.email() }),
    },

    -- VAULT SYNC ------------------------------------------------------------

    { name = "sync",          method = "GET", path = [[^/api/sync$]],                   no_body = true },
    { name = "config",        method = "GET", path = [[^/api/config$]],                 no_body = true },
    { name = "revision-date", method = "GET", path = [[^/api/accounts/revision-date$]], no_body = true },

    -- CIPHERS ---------------------------------------------------------------

    { name = "cipher list",   method = "GET",    path = [[^/api/ciphers$]],           no_body = true },
    {
      name         = "cipher create",
      method       = "POST",
      path         = [[^/api/ciphers$]],
      content_type = "application/json",
      json         = cipher_body,
    },
    {
      name         = "cipher update",
      method       = "PUT",
      path         = "^/api/ciphers/" .. U .. "$",
      content_type = "application/json",
      json         = cipher_body,
    },
    { name = "cipher get",         method = "GET",    path = "^/api/ciphers/" .. U .. "$",           no_body = true },
    { name = "cipher delete",      method = "DELETE", path = "^/api/ciphers/" .. U .. "$",           no_body = true },
    { name = "cipher soft-delete", method = "PUT",    path = "^/api/ciphers/" .. U .. "/delete$",    no_body = true },
    { name = "cipher restore",     method = "PUT",    path = "^/api/ciphers/" .. U .. "/restore$",   no_body = true },
    { name = "cipher share",       method = "PUT",    path = "^/api/ciphers/" .. U .. "/share$",     content_type = "application/json" },
    { name = "ciphers archive",    method = "PUT",    path = [[^/api/ciphers/archive$]],   content_type = "application/json", json = cipher_ids_body },
    { name = "ciphers unarchive",  method = "PUT",    path = [[^/api/ciphers/unarchive$]], content_type = "application/json", json = cipher_ids_body },
    { name = "ciphers import",     method = "POST",   path = [[^/api/ciphers/import$]],    content_type = "application/json" },
    { name = "ciphers bulk-delete",method = "DELETE", path = [[^/api/ciphers$]],           content_type = "application/json", json = cipher_ids_body },

    -- ATTACHMENTS -----------------------------------------------------------

    { name = "attachment create-v2", method = "POST",   path = "^/api/ciphers/" .. U .. "/attachment/v2$",
      content_type = "application/json", json = attachment_init_body },
    { name = "attachment get",       method = "GET",    path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "$", no_body = true },
    { name = "attachment upload",    method = "POST",   path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "$",
      content_type = "multipart/form-data" },
    { name = "attachment delete",    method = "DELETE", path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "$", no_body = true },

    -- FOLDERS ---------------------------------------------------------------

    { name = "folder list",   method = "GET",    path = [[^/api/folders$]],           no_body = true },
    { name = "folder create", method = "POST",   path = [[^/api/folders$]],           content_type = "application/json" },
    { name = "folder get",    method = "GET",    path = "^/api/folders/" .. U .. "$", no_body = true },
    { name = "folder update", method = "PUT",    path = "^/api/folders/" .. U .. "$", content_type = "application/json" },
    { name = "folder delete", method = "DELETE", path = "^/api/folders/" .. U .. "$", no_body = true },

    -- SENDS -----------------------------------------------------------------

    { name = "send list",        method = "GET",    path = [[^/api/sends$]],                                              no_body = true },
    { name = "send create",      method = "POST",   path = [[^/api/sends$]],
      content_type = "application/json", json = send_body },
    { name = "send create-file", method = "POST",   path = [[^/api/sends/file/v2$]],
      content_type = "application/json", json = send_body },
    { name = "send get",         method = "GET",    path = "^/api/sends/" .. U .. "$",   no_body = true },
    { name = "send update",      method = "PUT",    path = "^/api/sends/" .. U .. "$",   content_type = "application/json" },
    { name = "send delete",      method = "DELETE", path = "^/api/sends/" .. U .. "$",   no_body = true },
    { name = "send file upload", method = "POST",   path = "^/api/sends/" .. U .. "/file/" .. FILEID .. "$",
      content_type = "multipart/form-data" },
    { name = "send access",      method = "POST",   path = [[^/api/sends/[^/]+/access$]],
      content_type = "application/json", json = T.object({ password = nu_enc }) },

    -- ACCOUNT MANAGEMENT ----------------------------------------------------

    { name = "profile get",        method = "GET",    path = [[^/api/accounts/profile$]],           no_body = true },
    { name = "profile update",     method = "PUT",    path = [[^/api/accounts/profile$]],           content_type = "application/json" },
    { name = "avatar update",      method = "PUT",    path = [[^/api/accounts/avatar$]],            content_type = "application/json" },
    { name = "password change",    method = "POST",   path = [[^/api/accounts/password$]],          content_type = "application/json" },
    { name = "kdf change",         method = "POST",   path = [[^/api/accounts/kdf$]],               content_type = "application/json" },
    { name = "key update",         method = "POST",   path = [[^/api/accounts/key$]],               content_type = "application/json" },
    { name = "keys update",        method = "POST",   path = [[^/api/accounts/keys$]],              content_type = "application/json" },
    { name = "security stamp",     method = "POST",   path = [[^/api/accounts/security-stamp$]],    content_type = "application/json" },
    { name = "verify password",    method = "POST",   path = [[^/api/accounts/verify-password$]],   content_type = "application/json" },
    { name = "verify email",       method = "POST",   path = [[^/api/accounts/verify-email$]],         no_body = true },
    { name = "verify email token", method = "POST",   path = [[^/api/accounts/verify-email-token$]],  content_type = "application/json" },
    { name = "delete account",     method = "DELETE", path = [[^/api/accounts$]],
      content_type = "application/json",
      json = T.object({
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },

    -- TWO FACTOR ------------------------------------------------------------

    { name = "2fa list",          method = "GET",  path = [[^/api/two-factor$]],                   no_body = true },
    { name = "2fa get-recover",   method = "POST", path = [[^/api/two-factor/get-recover$]],       content_type = "application/json" },
    { name = "2fa recover",       method = "POST", path = [[^/api/two-factor/recover$]],           content_type = "application/json" },
    { name = "2fa get-webauthn",  method = "POST", path = [[^/api/two-factor/get-webauthn$]],      content_type = "application/json" },
    { name = "2fa get-duo",       method = "POST", path = [[^/api/two-factor/get-duo$]],           content_type = "application/json" },
    { name = "2fa get-totp",      method = "POST", path = [[^/api/two-factor/get-authenticator$]], content_type = "application/json" },
    { name = "2fa get-yubikey",   method = "POST", path = [[^/api/two-factor/get-yubikey$]],       content_type = "application/json" },
    { name = "2fa get-email",     method = "POST", path = [[^/api/two-factor/get-email$]],         content_type = "application/json" },
    { name = "2fa send-email",    method = "POST", path = [[^/api/two-factor/send-email-login$]],
      content_type = "application/json",
      json = T.object({
        email                 = T.nullable(T.email()),
        masterPasswordHash    = T.nullable(med),
        deviceIdentifier      = nu_uuid,
        authRequestId         = nu_uuid,
        authRequestAccessCode = T.nullable(T.string({ max=128 })),
      }) },

    -- DEVICES ---------------------------------------------------------------

    { name = "device list",        method = "GET",    path = [[^/api/devices$]],                          no_body = true },
    { name = "device by-id",       method = "GET",    path = "^/api/devices/identifier/" .. U .. "$",     no_body = true },
    { name = "device knowndevice", method = "GET",    path = [[^/api/devices/knowndevice$]],              no_body = true },
    { name = "device delete",      method = "DELETE", path = "^/api/devices/" .. U .. "$",                no_body = true },

    -- WEBAUTHN --------------------------------------------------------------

    { name = "webauthn list",    method = "GET",    path = [[^/api/webauthn$]],           no_body = true },
    { name = "webauthn create",  method = "POST",   path = [[^/api/webauthn$]],           content_type = "application/json" },
    { name = "webauthn delete",  method = "DELETE", path = "^/api/webauthn/" .. U .. "$", no_body = true },

    -- ORGANIZATIONS & COLLECTIONS -------------------------------------------

    { name = "org list",          method = "GET", path = [[^/api/organizations$]],                       no_body = true },
    { name = "collection list",   method = "GET", path = [[^/api/collections$]],                        no_body = true },
    { name = "org collections",   method = "GET", path = "^/api/organizations/" .. U .. "/collections$", no_body = true },
    { name = "org users",         method = "GET", path = "^/api/organizations/" .. U .. "/users$",       no_body = true },

    -- EMERGENCY ACCESS ------------------------------------------------------

    { name = "emergency trusted", method = "GET", path = [[^/api/emergency-access/trusted$]], no_body = true },
    { name = "emergency granted", method = "GET", path = [[^/api/emergency-access/granted$]], no_body = true },

    -- SETTINGS --------------------------------------------------------------

    { name = "domains get",    method = "GET", path = [[^/api/settings/domains$]], no_body = true },
    { name = "domains update", method = "PUT", path = [[^/api/settings/domains$]], content_type = "application/json" },

    -- PASSWORDLESS / AUTH REQUESTS ------------------------------------------

    { name = "auth-request list",   method = "GET",  path = [[^/api/auth-requests/pending$]],  no_body = true },
    { name = "auth-request create", method = "POST", path = [[^/api/auth-requests$]],          content_type = "application/json" },
    { name = "auth-request get",    method = "GET",  path = "^/api/auth-requests/" .. U .. "$", no_body = true },
    { name = "auth-request update", method = "PUT",  path = "^/api/auth-requests/" .. U .. "$", content_type = "application/json" },

    -- ICONS -----------------------------------------------------------------

    { name = "icons",              method = "GET", path = [[^/icons/[^/]+/icon\.png$]],    no_body = true },
    { name = "change-password-uri", method = "GET", path = [[^/icons/change-password-uri$]], no_body = true },

    -- NOTIFICATIONS (WebSocket) ---------------------------------------------
    -- nginx handles the actual upgrade; we only check that the method is GET

    { name = "notifications hub", method = "GET", path = [[^/notifications/hub$]],
      query = T.object({ access_token = vw_access_token }), no_body = true },

    -- ADMIN (IP-restricted to private networks) -----------------------------

    {
      name      = "admin",
      methods   = { "GET", "POST" },
      path      = [[^/admin(/|$)]],
      allow_ips = { "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12" },
    },

    -- STATIC WEB VAULT ASSETS -----------------------------------------------
    -- Filenames embed content hashes that change every release, so we use
    -- directory/extension patterns rather than enumerating each file.
    -- The existing PoC (vaultwarden_policy_handler.ljbc) lists them
    -- individually and includes a generate_webfiles_lua.sh script to
    -- regenerate after upgrades — the patterns below eliminate that chore.

    { name = "static root",    method = "GET", path = [[^/$]],                      no_body = true },
    { name = "static html",    method = "GET", path = [[^/[^/]+\.html$]],           no_body = true },
    { name = "static js",      method = "GET", path = [[^/.+\.js(\.map)?$]],        no_body = true },
    { name = "static css",     method = "GET", path = [[^/.+\.css(\.map)?$]],       no_body = true },
    { name = "static json",    method = "GET", path = [[^/[^/]+\.json$]],           no_body = true },
    { name = "static wasm",    method = "GET", path = [[^/.+\.wasm$]],              no_body = true },
    { name = "static xml",     method = "GET", path = [[^/[^/]+\.xml$]],            no_body = true },
    { name = "static txt",     method = "GET", path = [[^/.+\.txt$]],               no_body = true },
    { name = "app dir",        method = "GET", path = [[^/app(/|$)]],               no_body = true },
    { name = "connectors dir", method = "GET", path = [[^/connectors(/|$)]],        no_body = true },
    { name = "css dir",        method = "GET", path = [[^/css/]],                   no_body = true },
    { name = "fonts dir",      method = "GET", path = [[^/fonts/]],                 no_body = true },
    { name = "images dir",     method = "GET", path = [[^/images/]],                no_body = true },
    { name = "locales dir",    method = "GET", path = [[^/locales/]],               no_body = true },
    { name = "scripts dir",    method = "GET", path = [[^/scripts/]],               no_body = true },
    { name = "videos dir",     method = "GET", path = [[^/videos/]],                no_body = true },
    { name = "favicon",        method = "GET", path = [[^/favicon\.ico$]],          no_body = true },

  },
}
