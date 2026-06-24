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

-- Some Bitwarden fields send "" instead of null when unset (e.g. folderId
-- on a cipher with no folder).  T.nullable only passes nil/ngx.null; this
-- variant also accepts the empty string.
local nu_uuid_or_empty = function(v, path)
  if v == nil or v == ngx.null or v == "" then return true end
  return T.uuid()(v, path)
end

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

-- Passkey credential stored inside a login cipher (Bitwarden SDK: Fido2Key)
-- All fields are encrypted blobs; none are required.
local fido2_credential = T.object({
  credentialId    = nu_enc,
  keyType         = nu_enc,
  keyAlgorithm    = nu_enc,
  keyCurve        = nu_enc,
  keyValue        = nu_enc,
  rpId            = nu_enc,
  rpName          = nu_enc,
  counter         = nu_enc,
  userHandle      = nu_enc,
  userName        = nu_enc,
  userDisplayName = nu_enc,
  discoverable    = nu_enc,
  creationDate    = nu_enc,
  response        = nu_enc,
})

local cipher_body = T.object({
  -- type 5 = SshKey (added in Bitwarden SDK ~2024)
  type            = T.number({ integer = true, min = 1, max = 5 }),
  -- id is present in share/import contexts (the cipher's existing UUID)
  id              = nu_uuid,
  name            = enc,
  notes           = nu_enc,
  favorite        = nu_bool,
  folderId        = nu_uuid_or_empty,
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
    lastUsedDate = T.iso8601(),
    password     = enc,
  }), { max = 200 })),
  login = T.nullable(T.object({
    username             = nu_enc,
    password             = nu_enc,
    totp                 = nu_enc,
    uris                 = T.nullable(T.array(cipher_uri, { max = 100 })),
    passwordRevisionDate = T.nullable(T.iso8601()),
    autofillOnPageLoad   = nu_bool,
    fido2Credentials     = T.nullable(T.array(fido2_credential, { max = 50 })),
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
  sshKey = T.nullable(T.object({
    privateKey     = nu_enc,
    publicKey      = nu_enc,
    keyFingerprint = nu_enc,
    response       = nu_enc,
  })),
  archivedDate = T.nullable(T.iso8601()),
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
  key                   = enc,
  fileName              = enc,
  fileSize              = T.number({ integer=true, min=0, max=536870912 }),  -- 512 MB ceiling
  adminRequest          = nu_bool,
  lastKnownRevisionDate = T.nullable(T.iso8601()),
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
-- Shared auth-verification body: one of the two fields must be provided.
-- Used by security-stamp, verify-password, and all 2fa get-* endpoints.
-- (src/api/mod.rs: PasswordOrOtpData)
-- ---------------------------------------------------------------------------
local password_or_otp = T.object({
  masterPasswordHash = T.nullable(med),
  otp                = T.nullable(T.string({ max=16 })),
})

-- ---------------------------------------------------------------------------
-- KDF parameters — nested inside ChangeKdfData
-- Primary wire names are camelCase; serde aliases (kdfType, iterations, etc.)
-- are for backwards-compat deserialization only; clients send the primary names.
-- ---------------------------------------------------------------------------
local kdf_data = T.object({
  kdf            = T.number({ integer=true, min=0, max=1 }),  -- 0=PBKDF2, 1=Argon2id
  kdfIterations  = T.number({ integer=true, min=1, max=2000000 }),
  kdfMemory      = T.nullable(T.number({ integer=true, min=1, max=1048576 })),
  kdfParallelism = T.nullable(T.number({ integer=true, min=1, max=16 })),
})

-- Folder body: just an encrypted name
local folder_body = T.object({ name = enc })

-- Access-control entry shared by collection groups and collection members
-- (CollectionGroupData / CollectionMembershipData have the same wire shape)
local collection_access_entry = T.object({
  id            = T.uuid(),
  readOnly      = T.boolean(),
  hidePasswords = T.boolean(),
  manage        = T.boolean(),
})

-- Full collection body: used for collection create and update
-- (src/api/core/organizations.rs: FullCollectionData)
local full_collection_body = T.object({
  name       = enc,
  groups     = T.array(collection_access_entry, { max=500 }),
  users      = T.array(collection_access_entry, { max=500 }),
  id         = nu_uuid,
  externalId = T.nullable(T.string({ max=256 })),
})

-- Bulk UUID IDs body: shared by several bulk-operation endpoints
-- (BulkMembershipIds, BulkCollectionIds, etc.)
local bulk_uuid_ids = T.object({ ids = T.array(T.uuid(), { max=2000 }) })

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
-- JWT for the attachment file-download endpoint
-- iss = "https://<host>|file_download"
-- ---------------------------------------------------------------------------
local vw_file_token = T.jwt_claims({
  nbf     = T.number({ integer=true }),
  exp     = T.number({ integer=true }),
  iss     = T.string({ max=256, match=[[^https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+\|file_download$]] }),
  sub     = T.uuid(),
  file_id = T.string({ max=64 }),
}, {
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
      "x-device-identifier",
      "x-request-email",
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
      -- Device GUIDs sent by official clients to identify the registered device
      ["device-identifier"]      = T.uuid(),
      ["x-device-identifier"]    = T.uuid(),
      -- Base64-encoded email address sent by the web vault on some requests
      ["x-request-email"]        = T.base64({ max=256 }),
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
        grant_type        = T.string({ enum = { password = true, refresh_token = true, client_credentials = true, authorization_code = true } }),
        username          = T.nullable(T.email()),
        password          = T.nullable(med),
        -- "api" or "api offline_access"
        scope             = T.nullable(T.string({ max=32, match=[[^api( offline_access)?$]] })),
        client_id         = T.nullable(T.string({ max=16, enum={
          ["browser"]   = true,
          ["web"]       = true,
          ["desktop"]   = true,
          ["mobile"]    = true,
          ["cli"]       = true,
          ["connector"] = true,
        }})),
        client_secret     = nu_sml,
        refresh_token     = T.nullable(T.jwt()),
        -- form-encoded: values arrive as strings, not numbers
        deviceType        = T.nullable(T.string({ max=2, match=[[^(?:[0-9]|[12][0-9]|30)$]] })),
        deviceIdentifier  = T.nullable(T.uuid()),
        deviceName        = nu_sml,
        devicePushToken   = nu_sml,
        twoFactorToken    = T.nullable(T.string({ max=4096 })),  -- remember-me JWT, TOTP, WebAuthn, etc.
        twoFactorProvider = T.nullable(T.string({ max=2, match=[[^(?:[0-9]|10)$]] })),
        twoFactorRemember = T.nullable(T.string({ max=1, match=[[^[01]$]] })),
        captchaResponse   = nu_sml,
        authRequest       = T.nullable(T.uuid()),
        -- SSO / OIDC fields (grant_type="authorization_code")
        code              = T.nullable(T.string({ max=1024 })),
        code_verifier     = T.nullable(T.string({ max=256 })),
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

    { name = "tasks",         method = "GET", path = [[^/api/tasks$]],                  no_body = true },
    { name = "sync", method = "GET", path = [[^/api/sync$]], no_body = true,
      query = T.object({ excludeDomains = T.nullable(T.string({ max=5, match=[[^(?:true|false)?$]] })) }) },
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
    { name = "cipher admin get",   method = "GET",    path = "^/api/ciphers/" .. U .. "/admin$",     no_body = true },
    { name = "cipher delete",      method = "DELETE", path = "^/api/ciphers/" .. U .. "$",           no_body = true },
    { name = "cipher soft-delete", method = "PUT",    path = "^/api/ciphers/" .. U .. "/delete$",    no_body = true },
    { name = "cipher restore",     method = "PUT",    path = "^/api/ciphers/" .. U .. "/restore$",   no_body = true },
    { name = "cipher share", method = "PUT", path = "^/api/ciphers/" .. U .. "/share$",
      content_type = "application/json",
      json = T.object({
        cipher        = cipher_body,
        collectionIds = T.array(T.uuid(), { max = 200 }),
      }) },
    { name = "ciphers archive",   method = "PUT",  path = [[^/api/ciphers/archive$]],   content_type = "application/json", json = cipher_ids_body },
    { name = "ciphers unarchive", method = "PUT",  path = [[^/api/ciphers/unarchive$]], content_type = "application/json", json = cipher_ids_body },
    { name = "ciphers import",    method = "POST", path = [[^/api/ciphers/import$]],
      content_type = "application/json",
      json = T.object({
        ciphers = T.array(cipher_body, { max = 5000 }),
        folders = T.array(T.object({
          id   = nu_uuid,
          name = enc,
        }), { max = 1000 }),
        folderRelationships = T.array(T.object({
          key   = T.number({ integer=true, min=0 }),
          value = T.number({ integer=true, min=0 }),
        }), { max = 5000 }),
      }) },
    { name = "ciphers bulk-delete",method = "DELETE", path = [[^/api/ciphers$]],           content_type = "application/json", json = cipher_ids_body },
    -- Org-admin cipher create: same body shape as cipher share
    { name = "cipher admin create", method = "POST", path = [[^/api/ciphers/admin$]],
      content_type = "application/json",
      json = T.object({
        cipher        = cipher_body,
        collectionIds = T.array(T.uuid(), { max = 200 }),
      }) },
    -- Org cipher list: query param only, no body
    { name = "org cipher details", method = "GET", path = [[^/api/ciphers/organization-details$]],
      query = T.object({ organizationId = T.uuid() }), no_body = true },

    -- ATTACHMENTS -----------------------------------------------------------

    -- Direct attachment download: GET /attachments/{cipher_uuid}/{file_id}?token=<jwt>
    { name = "attachment download", method = "GET",
      path  = "^/attachments/" .. U .. "/" .. FILEID .. "$",
      query = T.object({ token = vw_file_token }),
      no_body = true },

    { name = "attachment create-v2", method = "POST",   path = "^/api/ciphers/" .. U .. "/attachment/v2$",
      content_type = "application/json", json = attachment_init_body },
    { name = "attachment get",       method = "GET",    path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "$", no_body = true },
    { name = "attachment upload",    method = "POST",   path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "$",
      content_type = "multipart/form-data" },
    { name = "attachment delete",    method = "DELETE", path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "$", no_body = true },

    -- FOLDERS ---------------------------------------------------------------

    { name = "folder list",   method = "GET",    path = [[^/api/folders$]],           no_body = true },
    { name = "folder create", method = "POST",   path = [[^/api/folders$]],           content_type = "application/json", json = folder_body },
    { name = "folder get",    method = "GET",    path = "^/api/folders/" .. U .. "$", no_body = true },
    { name = "folder update", method = "PUT",    path = "^/api/folders/" .. U .. "$", content_type = "application/json", json = folder_body },
    { name = "folder delete", method = "DELETE", path = "^/api/folders/" .. U .. "$", no_body = true },

    -- SENDS -----------------------------------------------------------------

    { name = "send list",        method = "GET",    path = [[^/api/sends$]],                                              no_body = true },
    { name = "send create",      method = "POST",   path = [[^/api/sends$]],
      content_type = "application/json", json = send_body },
    { name = "send create-file", method = "POST",   path = [[^/api/sends/file/v2$]],
      content_type = "application/json", json = send_body },
    { name = "send get",         method = "GET",    path = "^/api/sends/" .. U .. "$",   no_body = true },
    { name = "send update",      method = "PUT",    path = "^/api/sends/" .. U .. "$",   content_type = "application/json", json = send_body },
    { name = "send delete",      method = "DELETE", path = "^/api/sends/" .. U .. "$",   no_body = true },
    { name = "send file upload", method = "POST",   path = "^/api/sends/" .. U .. "/file/" .. FILEID .. "$",
      content_type = "multipart/form-data" },
    { name = "send access",      method = "POST",   path = [[^/api/sends/[^/]+/access$]],
      content_type = "application/json", json = T.object({ password = nu_enc }) },

    -- ACCOUNT MANAGEMENT ----------------------------------------------------

    { name = "profile get",        method = "GET",    path = [[^/api/accounts/profile$]],           no_body = true },
    { name = "profile update", methods = { "PUT", "POST" }, path = [[^/api/accounts/profile$]],
      content_type = "application/json",
      json = T.object({ name = T.string({ max=50 }) }) },
    { name = "avatar update", method = "PUT", path = [[^/api/accounts/avatar$]],
      content_type = "application/json",
      json = T.object({ avatarColor = T.nullable(T.string({ max=7, match=[[^#[0-9a-fA-F]{6}$]] })) }) },
    { name = "password change", method = "POST", path = [[^/api/accounts/password$]],
      content_type = "application/json",
      json = T.object({
        masterPasswordHash    = med,
        newMasterPasswordHash = med,
        masterPasswordHint    = T.nullable(sml),
        key                   = enc,
      }) },
    { name = "kdf change", method = "POST", path = [[^/api/accounts/kdf$]],
      content_type = "application/json",
      json = T.object({
        masterPasswordHash    = med,
        newMasterPasswordHash = med,
        key                   = enc,
        authenticationData = T.object({
          salt = sml,
          kdf  = kdf_data,
          masterPasswordAuthenticationHash = med,
        }),
        unlockData = T.object({
          salt                    = sml,
          kdf                     = kdf_data,
          masterKeyWrappedUserKey = enc,
        }),
      }) },
    -- /accounts/key does not exist in Vaultwarden; kept to avoid 404-before-proxy on old clients
    { name = "key update",  method = "POST", path = [[^/api/accounts/key$]],  content_type = "application/json" },
    { name = "keys update", method = "POST", path = [[^/api/accounts/keys$]],
      content_type = "application/json",
      json = T.object({
        encryptedPrivateKey = enc,
        publicKey           = T.string({ max=4096 }),
      }) },
    { name = "security stamp",  method = "POST", path = [[^/api/accounts/security-stamp$]],
      content_type = "application/json", json = password_or_otp },
    { name = "verify password", method = "POST", path = [[^/api/accounts/verify-password$]],
      content_type = "application/json",
      json = T.object({ masterPasswordHash = med }) },
    { name = "verify email",       method = "POST",   path = [[^/api/accounts/verify-email$]],         no_body = true },
    { name = "verify email token", method = "POST", path = [[^/api/accounts/verify-email-token$]],
      content_type = "application/json",
      json = T.object({
        userId = T.uuid(),
        token  = T.string({ max=1024 }),
      }) },
    { name = "delete account",     methods = { "DELETE", "POST" }, path = [[^/api/accounts(/delete)?$]],
      content_type = "application/json",
      json = T.object({
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },
    -- Account email-change: step 1 sends token, step 2 completes the change
    { name = "email-token", method = "POST", path = [[^/api/accounts/email-token$]],
      content_type = "application/json",
      json = T.object({
        masterPasswordHash = med,
        newEmail           = T.email(),
      }) },
    { name = "email change", method = "POST", path = [[^/api/accounts/email$]],
      content_type = "application/json",
      json = T.object({
        masterPasswordHash    = med,
        newEmail              = T.email(),
        key                   = enc,
        newMasterPasswordHash = med,
        token                 = T.string({ max=16 }),
      }) },
    -- Set password: used after SSO registration / invite with no prior password
    -- kdf fields are top-level (flattened from KDFData struct)
    { name = "set-password", method = "POST", path = [[^/api/accounts/set-password$]],
      content_type = "application/json",
      json = T.object({
        kdf             = T.number({ integer=true, min=0, max=1 }),
        kdfIterations   = T.number({ integer=true, min=1, max=2000000 }),
        kdfMemory       = T.nullable(T.number({ integer=true, min=1, max=1048576 })),
        kdfParallelism  = T.nullable(T.number({ integer=true, min=1, max=16 })),
        key             = enc,
        keys = T.nullable(T.object({
          encryptedPrivateKey = enc,
          publicKey           = T.string({ max=4096 }),
        })),
        masterPasswordHash = med,
        masterPasswordHint = T.nullable(sml),
        orgIdentifier      = T.nullable(T.string({ max=256 })),
      }) },
    -- Account key rotation: replaces all ciphers/folders with re-encrypted versions
    { name = "rotate-keys", method = "POST", path = [[^/api/accounts/key-management/rotate-user-account-keys$]],
      content_type = "application/json" },
    -- Delete recover: request and confirm account deletion by email
    { name = "delete-recover",       method = "POST", path = [[^/api/accounts/delete-recover$]],
      content_type = "application/json",
      json = T.object({ email = T.email() }) },
    { name = "delete-recover-token", method = "POST", path = [[^/api/accounts/delete-recover-token$]],
      content_type = "application/json",
      json = T.object({
        userId = T.uuid(),
        token  = T.string({ max=1024 }),
      }) },
    -- Password hint: unauthenticated endpoint
    { name = "password-hint", method = "POST", path = [[^/api/accounts/password-hint$]],
      content_type = "application/json",
      json = T.object({ email = T.email() }) },
    -- API key management: retrieve or rotate the user's CLI API key
    { name = "api-key",        method = "POST", path = [[^/api/accounts/api-key$]],        content_type = "application/json", json = password_or_otp },
    { name = "rotate-api-key", method = "POST", path = [[^/api/accounts/rotate-api-key$]], content_type = "application/json", json = password_or_otp },
    -- OTP-based protected actions (email OTP, distinct from 2FA)
    { name = "request-otp", method = "POST", path = [[^/api/accounts/request-otp$]], no_body = true },
    { name = "verify-otp",  method = "POST", path = [[^/api/accounts/verify-otp$]],
      content_type = "application/json",
      json_schemas = {
        T.object({ OTP = T.string({ max=16 }) }),
        T.object({ otp = T.string({ max=16 }) }),
      } },
    -- User public-key lookup (used by emergency-access, org confirm, etc.)
    { name = "user public-key", method = "GET", path = "^/api/users/" .. U .. "/public-key$", no_body = true },

    -- TWO FACTOR ------------------------------------------------------------

    { name = "2fa list",         method = "GET",  path = [[^/api/two-factor$]], no_body = true },
    -- All 2fa get-* endpoints require auth verification (PasswordOrOtpData)
    { name = "2fa get-recover",  method = "POST", path = [[^/api/two-factor/get-recover$]],       content_type = "application/json", json = password_or_otp },
    { name = "2fa get-webauthn", method = "POST", path = [[^/api/two-factor/get-webauthn$]],      content_type = "application/json", json = password_or_otp },
    { name = "2fa get-duo",      method = "POST", path = [[^/api/two-factor/get-duo$]],           content_type = "application/json", json = password_or_otp },
    { name = "2fa get-totp",     method = "POST", path = [[^/api/two-factor/get-authenticator$]], content_type = "application/json", json = password_or_otp },
    { name = "2fa get-yubikey",  method = "POST", path = [[^/api/two-factor/get-yubikey$]],       content_type = "application/json", json = password_or_otp },
    { name = "2fa get-email",    method = "POST", path = [[^/api/two-factor/get-email$]],         content_type = "application/json", json = password_or_otp },
    -- Recovery is handled via the login form (twoFactorProvider=6); this standalone
    -- endpoint is not implemented in Vaultwarden but exists on the official server.
    { name = "2fa recover",      method = "POST", path = [[^/api/two-factor/recover$]],
      content_type = "application/json",
      json = T.object({
        masterPasswordHash = T.nullable(med),
        recoveryCode       = T.nullable(T.string({ max=32 })),
        email              = T.nullable(T.email()),
      }) },
    { name = "2fa disable",       methods = { "POST", "PUT" }, path = [[^/api/two-factor/disable$]],
      content_type = "application/json",
      json = T.object({
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
        type               = T.number({ integer=true, min=0, max=255 }),
      }) },
    { name = "2fa device-verification-settings", method = "GET", path = [[^/api/two-factor/get-device-verification-settings$]], no_body = true },
    -- TOTP (authenticator app)
    { name = "2fa totp activate", methods = { "POST", "PUT" }, path = [[^/api/two-factor/authenticator$]],
      content_type = "application/json",
      json = T.object({
        key                = T.string({ max=256 }),
        token              = T.string({ max=16 }),
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },
    { name = "2fa totp delete",   method = "DELETE", path = [[^/api/two-factor/authenticator$]],
      content_type = "application/json",
      json = T.object({
        key                = T.string({ max=256 }),
        masterPasswordHash = med,
        type               = T.number({ integer=true, min=0, max=255 }),
      }) },
    -- YubiKey (hardware OTP key)
    { name = "2fa yubikey activate", methods = { "POST", "PUT" }, path = [[^/api/two-factor/yubikey$]],
      content_type = "application/json",
      json = T.object({
        key1 = T.nullable(T.string({ max=64 })),
        key2 = T.nullable(T.string({ max=64 })),
        key3 = T.nullable(T.string({ max=64 })),
        key4 = T.nullable(T.string({ max=64 })),
        key5 = T.nullable(T.string({ max=64 })),
        nfc  = T.boolean(),
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },
    -- Duo
    { name = "2fa duo activate", methods = { "POST", "PUT" }, path = [[^/api/two-factor/duo$]],
      content_type = "application/json",
      json = T.object({
        host               = T.string({ max=256 }),
        clientSecret       = T.string({ max=256 }),
        clientId           = T.string({ max=128 }),
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },
    -- Email 2FA: step 1 sends a code to the new address, step 2 activates it
    { name = "2fa send-email-setup", method = "POST", path = [[^/api/two-factor/send-email$]],
      content_type = "application/json",
      json = T.object({
        email              = T.email(),
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },
    { name = "2fa email activate", method = "PUT", path = [[^/api/two-factor/email$]],
      content_type = "application/json",
      json = T.object({
        email              = T.email(),
        token              = T.string({ max=16 }),
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },
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
    -- Device push token: register or update the push notification token for a device
    { name = "device push-token",  methods = { "POST", "PUT" }, path = "^/api/devices/identifier/" .. U .. "/token$",
      content_type = "application/json",
      json = T.object({ pushToken = T.string({ max=512 }) }) },
    -- Device clear-token: remove push token (PUT and POST are both supported upstream)
    { name = "device clear-token", methods = { "PUT", "POST" }, path = "^/api/devices/identifier/" .. U .. "/clear-token$",
      no_body = true },

    -- WEBAUTHN --------------------------------------------------------------

    -- WebAuthn routes are under /api/two-factor/webauthn, not /api/webauthn
    { name = "webauthn list",   method = "GET",    path = [[^/api/two-factor/webauthn$]], no_body = true },
    { name = "webauthn create", methods = { "POST", "PUT" }, path = [[^/api/two-factor/webauthn$]],
      content_type = "application/json",
      json = T.object({
        id   = T.number({ integer=true, min=1, max=5 }),
        name = T.string({ max=256 }),
        deviceResponse = T.object({
          id     = T.string({ max=512 }),
          rawId  = T.string({ max=512 }),
          type   = T.string({ max=32 }),
          response = T.object({
            attestationObject = T.string({ max=65536 }),
            clientDataJson    = T.string({ max=65536 }),
          }),
        }),
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },
    { name = "webauthn delete", method = "DELETE", path = [[^/api/two-factor/webauthn$]],
      content_type = "application/json",
      json = T.object({
        id                 = T.number({ integer=true, min=1, max=5 }),
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },

    -- ORGANIZATIONS & COLLECTIONS -------------------------------------------

    { name = "org list",   method = "GET",  path = [[^/api/organizations$]], no_body = true },
    { name = "org get",    method = "GET",  path = "^/api/organizations/" .. U .. "$", no_body = true },
    { name = "org update", methods = { "PUT", "POST" }, path = "^/api/organizations/" .. U .. "$",
      content_type = "application/json",
      json = T.object({ billingEmail = T.email(), name = T.string({ max=256 }) }) },
    { name = "org delete", method = "DELETE", path = "^/api/organizations/" .. U .. "$",
      content_type = "application/json", json = password_or_otp },
    { name = "org delete-post", method = "POST", path = "^/api/organizations/" .. U .. "/delete$",
      content_type = "application/json", json = password_or_otp },
    { name = "org leave", method = "POST", path = "^/api/organizations/" .. U .. "/leave$", no_body = true },
    -- Auto-enroll status: identifier may be a UUID or a special SSO string
    { name = "org auto-enroll-status", method = "GET", path = [[^/api/organizations/[^/]+/auto-enroll-status$]], no_body = true },
    { name = "org keys", method = "POST", path = "^/api/organizations/" .. U .. "/keys$",
      content_type = "application/json",
      json = T.object({ encryptedPrivateKey = enc, publicKey = T.string({ max=4096 }) }) },
    -- SSO domain stub: always returns a dummy value
    { name = "org sso-verified", method = "POST", path = [[^/api/organizations/domain/sso/verified$]], no_body = true },
    { name = "org create", method = "POST", path = [[^/api/organizations$]],
      content_type = "application/json",
      json = T.object({
        billingEmail   = T.email(),
        collectionName = enc,
        key            = enc,
        name           = T.string({ max=256 }),
        planType       = T.nullable(T.number({ integer=true, min=0, max=100 })),
        keys = T.nullable(T.object({
          encryptedPrivateKey = enc,
          publicKey           = T.string({ max=4096 }),
        })),
      }) },
    { name = "collection list",        method = "GET", path = [[^/api/collections$]],                              no_body = true },
    { name = "org collections",        method = "GET", path = "^/api/organizations/" .. U .. "/collections$",      no_body = true },
    { name = "org collections details",method = "GET", path = "^/api/organizations/" .. U .. "/collections/details$", no_body = true },
    -- Collection CRUD
    { name = "org collection create", method = "POST", path = "^/api/organizations/" .. U .. "/collections$",
      content_type = "application/json", json = full_collection_body },
    { name = "org collection bulk-access", method = "POST", path = "^/api/organizations/" .. U .. "/collections/bulk-access$",
      content_type = "application/json",
      json = T.object({
        collectionIds = T.array(T.uuid(), { max=500 }),
        groups        = T.array(collection_access_entry, { max=500 }),
        users         = T.array(collection_access_entry, { max=500 }),
      }) },
    { name = "org collection update",  methods = { "PUT", "POST" }, path = "^/api/organizations/" .. U .. "/collections/" .. U .. "$",
      content_type = "application/json", json = full_collection_body },
    { name = "org collection delete",  method = "DELETE", path = "^/api/organizations/" .. U .. "/collections/" .. U .. "$",  no_body = true },
    { name = "org collection delete-post", method = "POST", path = "^/api/organizations/" .. U .. "/collections/" .. U .. "/delete$", no_body = true },
    { name = "org collections bulk-delete", method = "DELETE", path = "^/api/organizations/" .. U .. "/collections$",
      content_type = "application/json", json = bulk_uuid_ids },
    { name = "org collection details", method = "GET",  path = "^/api/organizations/" .. U .. "/collections/" .. U .. "/details$", no_body = true },
    { name = "org collection users",   method = "GET",  path = "^/api/organizations/" .. U .. "/collections/" .. U .. "/users$",   no_body = true },
    { name = "org groups",             method = "GET", path = "^/api/organizations/" .. U .. "/groups$",            no_body = true },
    -- Org user management
    { name = "org users", method = "GET", path = "^/api/organizations/" .. U .. "/users$", no_body = true,
      query = T.object({
        includeCollections = T.nullable(T.string({ max=5, match=[[^(?:true|false)?$]] })),
        includeGroups      = T.nullable(T.string({ max=5, match=[[^(?:true|false)?$]] })),
      }) },
    { name = "org user mini-details", method = "GET", path = "^/api/organizations/" .. U .. "/users/mini-details$", no_body = true },
    { name = "org user get",     method = "GET", path = "^/api/organizations/" .. U .. "/users/" .. U .. "$", no_body = true,
      query = T.object({
        includeCollections = T.nullable(T.string({ max=5, match=[[^(?:true|false)?$]] })),
        includeGroups      = T.nullable(T.string({ max=5, match=[[^(?:true|false)?$]] })),
      }) },
    { name = "org user update",  methods = { "PUT", "POST" }, path = "^/api/organizations/" .. U .. "/users/" .. U .. "$",
      content_type = "application/json",
      json = T.object({
        type        = T.number({ integer=true, min=0, max=4 }),
        collections = T.nullable(T.array(collection_access_entry, { max=500 })),
        groups      = T.nullable(T.array(T.uuid(), { max=500 })),
        permissions = T.nullable(T.dict(T.nullable(T.boolean()))),
      }) },
    { name = "org user delete",  method = "DELETE", path = "^/api/organizations/" .. U .. "/users/" .. U .. "$", no_body = true },
    { name = "org users invite",  method = "POST", path = "^/api/organizations/" .. U .. "/users/invite$",
      content_type = "application/json",
      json = T.object({
        emails      = T.array(T.email(), { max=200 }),
        groups      = T.array(T.uuid(), { max=200 }),
        type        = T.number({ integer=true, min=0, max=4 }),
        collections = T.nullable(T.array(collection_access_entry, { max=500 })),
        permissions = T.nullable(T.dict(T.nullable(T.boolean()))),
      }) },
    { name = "org users reinvite-bulk", method = "POST", path = "^/api/organizations/" .. U .. "/users/reinvite$",
      content_type = "application/json", json = bulk_uuid_ids },
    { name = "org user reinvite", method = "POST", path = "^/api/organizations/" .. U .. "/users/" .. U .. "/reinvite$", no_body = true },
    { name = "org user accept",  method = "POST", path = "^/api/organizations/" .. U .. "/users/" .. U .. "/accept$",
      content_type = "application/json",
      json = T.object({
        token            = T.string({ max=4096 }),
        resetPasswordKey = T.nullable(enc),
      }) },
    { name = "org users confirm-bulk", method = "POST", path = "^/api/organizations/" .. U .. "/users/confirm$",
      content_type = "application/json",
      json = T.object({
        keys = T.nullable(T.array(T.object({
          id  = nu_uuid,
          key = T.nullable(enc),
        }), { max=500 })),
      }) },
    { name = "org user confirm",  method = "POST", path = "^/api/organizations/" .. U .. "/users/" .. U .. "/confirm$",
      content_type = "application/json",
      json = T.object({ id = nu_uuid, key = T.nullable(enc) }) },
    { name = "org users bulk-delete", method = "DELETE", path = "^/api/organizations/" .. U .. "/users$",
      content_type = "application/json", json = bulk_uuid_ids },
    { name = "org users public-keys", method = "POST", path = "^/api/organizations/" .. U .. "/users/public-keys$",
      content_type = "application/json", json = bulk_uuid_ids },

    -- EMERGENCY ACCESS ------------------------------------------------------

    { name = "emergency trusted", method = "GET", path = [[^/api/emergency-access/trusted$]], no_body = true },
    { name = "emergency granted", method = "GET", path = [[^/api/emergency-access/granted$]], no_body = true },
    { name = "emergency invite",  method = "POST", path = [[^/api/emergency-access/invite$]],
      content_type = "application/json",
      json = T.object({
        email        = T.email(),
        type         = T.number({ integer=true, min=0, max=1 }),
        waitTimeDays = T.number({ integer=true, min=1, max=90 }),
      }) },
    { name = "emergency get",     method = "GET",    path = "^/api/emergency-access/" .. U .. "$",                no_body = true },
    { name = "emergency update",  methods = { "PUT", "POST" }, path = "^/api/emergency-access/" .. U .. "$",
      content_type = "application/json",
      json = T.object({
        type         = T.number({ integer=true, min=0, max=1 }),
        waitTimeDays = T.number({ integer=true, min=1, max=90 }),
        keyEncrypted = nu_enc,
      }) },
    { name = "emergency delete",  methods = { "DELETE" }, path = "^/api/emergency-access/" .. U .. "$",           no_body = true },
    { name = "emergency delete-post", method = "POST", path = "^/api/emergency-access/" .. U .. "/delete$",       no_body = true },
    { name = "emergency reinvite",    method = "POST", path = "^/api/emergency-access/" .. U .. "/reinvite$",     no_body = true },
    { name = "emergency accept",      method = "POST", path = "^/api/emergency-access/" .. U .. "/accept$",
      content_type = "application/json",
      json = T.object({ token = T.string({ max=4096 }) }) },
    { name = "emergency confirm",     method = "POST", path = "^/api/emergency-access/" .. U .. "/confirm$",
      content_type = "application/json",
      json = T.object({ key = enc }) },
    { name = "emergency initiate",    method = "POST", path = "^/api/emergency-access/" .. U .. "/initiate$",     no_body = true },
    { name = "emergency approve",     method = "POST", path = "^/api/emergency-access/" .. U .. "/approve$",      no_body = true },
    { name = "emergency reject",      method = "POST", path = "^/api/emergency-access/" .. U .. "/reject$",       no_body = true },
    { name = "emergency view",        method = "POST", path = "^/api/emergency-access/" .. U .. "/view$",         no_body = true },
    { name = "emergency takeover",    method = "POST", path = "^/api/emergency-access/" .. U .. "/takeover$",     no_body = true },
    { name = "emergency password",    method = "POST", path = "^/api/emergency-access/" .. U .. "/password$",
      content_type = "application/json",
      json = T.object({
        newMasterPasswordHash = med,
        key                   = enc,
      }) },
    { name = "emergency policies",    method = "GET",  path = "^/api/emergency-access/" .. U .. "/policies$",     no_body = true },

    -- SETTINGS --------------------------------------------------------------

    { name = "domains get",    method = "GET", path = [[^/api/settings/domains$]], no_body = true },
    { name = "domains update", method = "PUT", path = [[^/api/settings/domains$]],
      content_type = "application/json",
      json = T.object({
        excludedGlobalEquivalentDomains = T.nullable(T.array(T.number({ integer=true, min=0 }), { max=100 })),
        equivalentDomains               = T.nullable(T.array(T.array(T.string({ max=256 }), { max=50 }), { max=100 })),
      }) },

    -- PASSWORDLESS / AUTH REQUESTS ------------------------------------------

    -- Legacy alias for /pending; still sent by some older clients
    { name = "auth-request list-all", method = "GET", path = [[^/api/auth-requests$]], no_body = true },
    { name = "auth-request list",   method = "GET",  path = [[^/api/auth-requests/pending$]],  no_body = true },
    -- Auth-request response poll: the initiating device polls this to get the approval
    { name = "auth-request response", method = "GET", path = "^/api/auth-requests/" .. U .. "/response$",
      query = T.object({ code = T.string({ max=64 }) }), no_body = true },
    { name = "auth-request create", method = "POST", path = [[^/api/auth-requests$]],
      content_type = "application/json",
      json = T.object({
        accessCode       = T.string({ max=25 }),
        deviceIdentifier = T.uuid(),
        email            = T.email(),
        publicKey        = T.string({ max=4096 }),
      }) },
    { name = "auth-request get",    method = "GET",  path = "^/api/auth-requests/" .. U .. "$", no_body = true },
    { name = "auth-request update", method = "PUT",  path = "^/api/auth-requests/" .. U .. "$",
      content_type = "application/json",
      json = T.object({
        deviceIdentifier   = T.uuid(),
        key                = enc,
        masterPasswordHash = T.nullable(med),
        requestApproved    = T.boolean(),
      }) },

    -- ICONS -----------------------------------------------------------------

    { name = "icons",              method = "GET", path = [[^/icons/[^/]+/icon\.png$]],    no_body = true },
    { name = "change-password-uri", method = "GET", path = [[^/icons/change-password-uri$]], no_body = true },

    -- NOTIFICATIONS (WebSocket) ---------------------------------------------
    -- nginx handles the actual upgrade; we only check that the method is GET

    { name = "notifications hub", method = "GET", path = [[^/notifications/hub$]],
      query = T.object({ access_token = vw_access_token }), no_body = true },

    -- ADMIN PANEL -----------------------------------------------------------
    -- Routes are listed most-specific-first so the parameterized catch-all
    -- for /admin/users/<uuid> does not shadow the named sub-paths.

    -- Landing page (GET) and form login (POST)
    { name = "admin page",  method = "GET",  path = [[^/admin/?$]], no_body = true },
    { name = "admin login", method = "POST", path = [[^/admin/?$]],
      content_types = { "application/x-www-form-urlencoded" },
      form_schemas  = { T.object({
        token    = T.string({ max = 1024 }),
        redirect = T.nullable(T.string({ max = 1024 })),
      }) },
    },

    { name = "admin logout", method = "GET", path = [[^/admin/logout$]], no_body = true },

    { name = "admin invite",    method = "POST", path = [[^/admin/invite$]],
      content_types = { "application/json" },
      json_schemas  = { T.object({ email = T.email() }) },
    },
    { name = "admin test smtp", method = "POST", path = [[^/admin/test/smtp$]],
      content_types = { "application/json" },
      json_schemas  = { T.object({ email = T.email() }) },
    },

    -- User management — specific named paths before the parameterized /<uuid> route
    { name = "admin users list",            method = "GET",  path = [[^/admin/users$]],                  no_body = true },
    { name = "admin users overview",        method = "GET",  path = [[^/admin/users/overview$]],         no_body = true },
    { name = "admin users org-type",        method = "POST", path = [[^/admin/users/org_type$]],
      content_types = { "application/json" },
      json_schemas  = { T.object({
        user_type = T.number({ integer = true, min = 0, max = 255 }),
        user_uuid = T.uuid(),
        org_uuid  = T.uuid(),
      }) },
    },
    { name = "admin users update-revision", method = "POST", path = [[^/admin/users/update_revision$]],  no_body = true },
    { name = "admin users by-mail",         method = "GET",  path = [[^/admin/users/by-mail/[^/]+$]],   no_body = true },

    -- Per-user actions — sub-paths before the bare /<uuid> route
    { name = "admin user invite resend", method = "POST",   path = "^/admin/users/" .. U .. "/invite/resend$", no_body = true },
    { name = "admin user delete",        method = "POST",   path = "^/admin/users/" .. U .. "/delete$",        no_body = true },
    { name = "admin user sso delete",    method = "DELETE", path = "^/admin/users/" .. U .. "/sso$",           no_body = true },
    { name = "admin user deauth",        method = "POST",   path = "^/admin/users/" .. U .. "/deauth$",        no_body = true },
    { name = "admin user disable",       method = "POST",   path = "^/admin/users/" .. U .. "/disable$",       no_body = true },
    { name = "admin user enable",        method = "POST",   path = "^/admin/users/" .. U .. "/enable$",        no_body = true },
    { name = "admin user remove-2fa",    method = "POST",   path = "^/admin/users/" .. U .. "/remove-2fa$",    no_body = true },
    { name = "admin user get",           method = "GET",    path = "^/admin/users/" .. U .. "$",               no_body = true },

    -- Organizations
    { name = "admin orgs overview", method = "GET",  path = [[^/admin/organizations/overview$]],          no_body = true },
    { name = "admin org delete",    method = "POST", path = "^/admin/organizations/" .. U .. "/delete$",  no_body = true },

    -- Diagnostics
    { name = "admin diagnostics",        method = "GET", path = [[^/admin/diagnostics$]],        no_body = true },
    { name = "admin diagnostics config", method = "GET", path = [[^/admin/diagnostics/config$]], no_body = true },
    { name = "admin diagnostics http",   method = "GET", path = [[^/admin/diagnostics/http$]],
      no_body = true,
      query   = T.object({ code = T.string({ max = 5, match = [[^\d+$]] }) }),
    },

    -- Config management
    { name = "admin config post",      method = "POST", path = [[^/admin/config$]],
      content_types = { "application/json" }, max_body = 1024 * 1024,
    },
    { name = "admin config delete",    method = "POST", path = [[^/admin/config/delete$]],    no_body = true },
    { name = "admin config backup-db", method = "POST", path = [[^/admin/config/backup_db$]], no_body = true },

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
