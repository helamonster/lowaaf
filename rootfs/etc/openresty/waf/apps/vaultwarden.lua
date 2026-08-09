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
-- vaultwarden.lua : LOWAAF for Vaultwarden
--
-- Vaultwarden: The Unofficial Bitwarden compatible server written in Rust
-- <https://github.com/dani-garcia/vaultwarden>
-- <https://www.vaultwarden.net/>
--
-- --------------------------------------------------------------------------------------

local T    = require "waf.types"
local core = require "waf.core"

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
-- Wrapped with T.with_check so T._registry is populated and gen.lua can
-- produce invalid UA test cases automatically (unrecognized bot UAs as hints).
local function ua_any_known()
  local clients = { ua_web(), ua_mobile(), ua_desktop(), ua_cli() }
  local base = T.string({ max = 512 })
  return T.with_check(base, function(v, path)
    for _, check in ipairs(clients) do
      if check(v, path) then return true end
    end
    return false, path .. ": unrecognized Bitwarden client user-agent"
  end, {
    { value = "BadBot/1.0",           label = "unrecognized UA" },
    { value = "curl/7.81.0",          label = "curl UA" },
    { value = "python-requests/2.28", label = "python-requests UA" },
  })
end

-- ---------------------------------------------------------------------------
-- shared type aliases
-- ---------------------------------------------------------------------------
local enc     = T.string({ max = 10000, not_match = "[\\x00-\\x1f]" })  -- Bitwarden-encrypted ciphertext blob (2.<iv>|<data>|<mac>)
local sml     = T.string({ max = 256,   not_match = "[\\x00-\\x1f]" })  -- short freetext: names, labels, hints, short hashes
local med     = T.string({ max = 2048,  not_match = "[\\x00-\\x1f]" })  -- medium freetext: password hashes, JWT-sized tokens
local nu_enc  = T.nullable(enc)            -- nullable encrypted blob
local nu_uuid = T.nullable(T.uuid())       -- nullable UUID
local nu_bool = T.nullable(T.boolean())    -- nullable boolean
local nu_num  = T.nullable(T.number({ integer = true }))  -- nullable integer
local nu_sml  = T.nullable(sml)            -- nullable short string
local nu_kdf_memory      = T.nullable(T.number({ integer=true, min=1, max=1048576 }))
local nu_kdf_parallelism = T.nullable(T.number({ integer=true, min=1, max=16 }))

-- Some Bitwarden fields send "" instead of null when unset (e.g. folderId
-- on a cipher with no folder).  T.nullable only passes nil/ngx.null; this
-- variant also accepts the empty string.
local nu_uuid_or_empty = function(v, path)
  if v == nil or v == ngx.null or v == "" then return true end
  return T.uuid()(v, path)
end
T._registry[nu_uuid_or_empty] = { type = "uuid_or_empty" }

-- Path-pattern regex fragments (sourced from types.lua for single-source-of-truth)
local U      = T.uuid_re    -- UUID segment in route paths
local FILEID = T.fileid_re  -- base64url file ID segment (attachments, Send files)

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
  linkedId = T.nullable(T.number({ integer=true, min=0, max=500 })),
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

-- Enforces that each cipher type includes its mandatory sub-object.
-- Bitwarden: 1=Login, 2=SecureNote, 3=Card, 4=Identity, 5=SshKey
local cipher_type_hints = {
  { value = { type=1, name="a" }, label = "type=1 without login sub-object"      },
  { value = { type=2, name="a" }, label = "type=2 without secureNote sub-object" },
  { value = { type=3, name="a" }, label = "type=3 without card sub-object"       },
  { value = { type=4, name="a" }, label = "type=4 without identity sub-object"   },
  { value = { type=5, name="a" }, label = "type=5 without sshKey sub-object"     },
}

local function cipher_type_check(v, path)
  if type(v) ~= "table" then return true end
  local required = { [1]="login", [2]="secureNote", [3]="card", [4]="identity", [5]="sshKey" }
  local sub = required[v.type]
  if sub and (v[sub] == nil or v[sub] == ngx.null) then
    return false, path .. ": cipher type=" .. tostring(v.type)
                       .. " requires sub-object '" .. sub .. "'"
  end
  return true
end

local cipher_body = T.with_check(T.object({
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
    fileSize              = T.nullable(T.number({ integer=true, min=0, max=536870912 })),
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
}, { required = { type=true, name=true } }), cipher_type_check, cipher_type_hints, {
  -- Coordinated multi-field variants: type + its mandatory sub-object.
  -- Single-field substitution in gen.lua cannot produce these because changing
  -- type alone fails cipher_type_check (sub-object absent).
  { value = { type=2, name="a", secureNote={} }, label = "type=2 (SecureNote)" },
  { value = { type=3, name="a", card={} },       label = "type=3 (Card)"       },
  { value = { type=4, name="a", identity={} },   label = "type=4 (Identity)"   },
  { value = { type=5, name="a", sshKey={} },     label = "type=5 (SshKey)"     },
})

-- Share-cipher body: shared by "cipher share", "cipher admin create", and
-- "cipher create-post" (src/api/core/ciphers.rs: ShareCipherData). Serde
-- aliases mean older/mobile clients may send PascalCase "Cipher"/
-- "CollectionIds" instead of "cipher"/"collectionIds"; both are allowed.
local share_cipher_body = T.object({
  cipher        = cipher_body,
  Cipher        = cipher_body,
  collectionIds = T.array(T.uuid(), { max = 200 }),
  CollectionIds = T.array(T.uuid(), { max = 200 }),
})

-- ---------------------------------------------------------------------------
-- Registration body: shared by the legacy /identity/accounts/register and
-- the new two-step /identity/accounts/register/finish.
-- (src/api/core/accounts.rs: RegisterData)
-- Serde aliases mean clients send either "key" or "userSymmetricKey" and
-- either "keys" or "userAsymmetricKeys"; both names are allowed here.
-- ---------------------------------------------------------------------------
local asym_keys_schema = { encryptedPrivateKey = enc, publicKey = T.string({ max=4096 }) }
local asym_keys_body   = T.object(asym_keys_schema)
local keys_data        = T.nullable(T.object(asym_keys_schema, { required = { encryptedPrivateKey=true, publicKey=true } }))

-- RegisterData.key (accounts.rs:100) is a required String, aliased as
-- userSymmetricKey by newer clients. opts.required can only enforce a single
-- fixed key name, not "one of these two aliases", so that constraint needs an
-- explicit cross-field check (same with_check pattern as cipher_type_check).
local function register_key_check(v, path)
  if type(v) ~= "table" then return true end
  local has_key   = v.key ~= nil and v.key ~= ngx.null
  local has_alias = v.userSymmetricKey ~= nil and v.userSymmetricKey ~= ngx.null
  if not has_key and not has_alias then
    return false, path .. ": one of 'key' or 'userSymmetricKey' is required"
  end
  return true
end

local register_body = T.with_check(T.object({
  email              = T.email(),
  kdf                = T.number({ integer=true, min=0, max=1 }),
  kdfIterations      = T.number({ integer=true, min=1, max=2000000 }),
  kdfMemory          = nu_kdf_memory,
  kdfParallelism     = nu_kdf_parallelism,
  key                = T.nullable(enc),   -- serde primary name
  userSymmetricKey   = T.nullable(enc),   -- serde alias sent by newer clients
  keys               = keys_data,         -- serde primary name
  userAsymmetricKeys = keys_data,         -- serde alias sent by newer clients
  masterPasswordHash = med,
  masterPasswordHint = nu_sml,
  name               = nu_sml,
  organizationUserId = nu_uuid,
  -- register/finish only: verification token returned by send-verification-email
  emailVerificationToken           = T.nullable(T.string({ max=4096 })),
  acceptEmergencyAccessId          = nu_uuid,
  acceptEmergencyAccessInviteToken = T.nullable(T.string({ max=4096 })),
  orgInviteToken     = T.nullable(T.string({ max=4096 })),  -- serde primary name
  token              = T.nullable(T.string({ max=4096 })),  -- serde alias
}, { required = { email=true, kdf=true, kdfIterations=true, masterPasswordHash=true } }), register_key_check, {
  { value = { email="a@a.com", kdf=0, kdfIterations=1, masterPasswordHash="a" },
    label = "key and userSymmetricKey both absent" },
})

-- ---------------------------------------------------------------------------
-- Shared body for bulk cipher operations: archive, unarchive, bulk-delete
-- (src/api/core/ciphers.rs: CipherIdsData)
-- ---------------------------------------------------------------------------
local cipher_ids_body = T.object({
  ids            = T.array(T.uuid(), { max = 2000 }),
  organizationId = nu_uuid,
}, { required = { ids=true } })

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
}, { required = { key=true, fileName=true, fileSize=true } })

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
  password       = T.nullable(sml),   -- PBKDF2-derived 44-char base64 key; sml (256) gives headroom
  -- Rust: Option<NumberOrString> (src/api/core/sends.rs) -- clients inconsistently
  -- send these as a JSON number or a numeric string.
  maxAccessCount = T.nullable(T.number_or_string({ integer=true, min=0, max=1000000 })),
  expirationDate = T.nullable(T.iso8601()),
  hideEmail      = nu_bool,
  accessCount    = T.nullable(T.number({ integer=true, min=0, max=1000000 })),
  notes          = nu_enc,
  fileLength     = T.nullable(T.number_or_string({ integer=true, min=0, max=536870912 })),
  id             = nu_uuid,
  -- bw CLI v2026+: email notification list and send auth type
  emails         = T.nullable(T.array(T.email(), { max=1000 })),
  authType       = T.nullable(T.number({ integer=true, min=0, max=10 })),
  text = T.nullable(T.object({
    text     = nu_enc,
    hidden   = nu_bool,
    response = T.nullable(T.string({ max=65536 })),  -- server-side plaintext; null on create/update
  })),
  file = T.nullable(T.object({
    fileName = nu_enc,
    id       = nu_uuid,
    size     = T.nullable(T.string({ max=32 })),
    sizeName = T.nullable(T.string({ max=32 })),
  })),
}, { required = { type=true, key=true, name=true, deletionDate=true, disabled=true } })

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
-- KDF parameters — nested inside ChangeKdfData (used by kdf-change via kdf = kdf_data).
-- Primary wire names are camelCase; serde aliases (kdfType, iterations, etc.)
-- are for backwards-compat deserialization only; clients send the primary names.
-- NOTE: set-password has the same four fields but flattened at the top level of
-- its request body — the nesting differs, so kdf_data cannot be reused there.
-- ---------------------------------------------------------------------------
local kdf_data = T.object({
  kdf            = T.number({ integer=true, min=0, max=1 }),  -- 0=PBKDF2, 1=Argon2id
  kdfIterations  = T.number({ integer=true, min=1, max=2000000 }),
  kdfMemory      = nu_kdf_memory,
  kdfParallelism = nu_kdf_parallelism,
}, { required = { kdf=true, kdfIterations=true } })

-- Folder body: encrypted name plus an optional id (src/api/core/folders.rs:
-- FolderData.id — accepted on both create and update, though the server
-- ignores it on create and the path param wins on update)
local folder_body = T.object({ name = enc, id = nu_uuid_or_empty }, { required = { name=true } })

-- Access-control entry shared by collection groups and collection members
-- (CollectionGroupData / CollectionMembershipData have the same wire shape)
local collection_access_entry = T.object({
  id            = T.uuid(),
  readOnly      = T.boolean(),
  hidePasswords = T.boolean(),
  manage        = T.boolean(),
}, { required = { id=true, readOnly=true, hidePasswords=true, manage=true } })

-- Full collection body: used for collection create and update
-- (src/api/core/organizations.rs: FullCollectionData)
local full_collection_body = T.object({
  name       = enc,
  groups     = T.array(collection_access_entry, { max=500 }),
  users      = T.array(collection_access_entry, { max=500 }),
  id         = nu_uuid,
  externalId = T.nullable(T.string({ max=256 })),
}, { required = { name=true, groups=true, users=true } })

-- Bulk UUID IDs body: shared by several bulk-operation endpoints
-- (BulkMembershipIds, BulkCollectionIds, etc.)
local bulk_uuid_ids = T.object({ ids = T.array(T.uuid(), { max=2000 }) }, { required = { ids=true } })

-- Org member custom-role permissions: server-side this is an untyped
-- HashMap<String, Value> (organizations.rs: InviteData/EditUserData.permissions),
-- but the real request body is always built from the client's PermissionsApi
-- class (bitwarden/clients: libs/common/src/admin-console/models/api/permissions.api.ts),
-- a fixed set of 13 camelCase boolean keys. T.dict(...) would accept any key
-- name; using the closed key set here instead so an unrecognized key is rejected.
local permissions_body = T.object({
  accessEventLogs      = T.nullable(T.boolean()),
  accessImportExport   = T.nullable(T.boolean()),
  accessReports        = T.nullable(T.boolean()),
  createNewCollections = T.nullable(T.boolean()),
  editAnyCollection    = T.nullable(T.boolean()),
  deleteAnyCollection  = T.nullable(T.boolean()),
  manageCiphers        = T.nullable(T.boolean()),
  manageGroups         = T.nullable(T.boolean()),
  manageSso            = T.nullable(T.boolean()),
  managePolicies       = T.nullable(T.boolean()),
  manageUsers          = T.nullable(T.boolean()),
  manageResetPassword  = T.nullable(T.boolean()),
  manageScim           = T.nullable(T.boolean()),
})

-- Partial cipher update: folderId and favorite only (src/api/core/ciphers.rs: PartialCipherData)
local cipher_partial_body = T.object({
  name     = T.nullable(enc),
  folderId = nu_uuid_or_empty,
  favorite = T.boolean(),
}, { required = { favorite=true } })

-- Collection-assignment body: used by /collections, /collections_v2, /collections-admin
-- (CollectionsAdminData — primary field collectionIds, #[serde(alias = "CollectionIds")]
-- means legacy/mobile clients may send the PascalCase form instead)
local cipher_collections_body = T.object({
  collectionIds = T.array(T.uuid(), { max=200 }),
  CollectionIds = T.array(T.uuid(), { max=200 }),
})

-- Settings: equivalent domain groupings
-- (src/api/core/accounts.rs: EquivalentDomainData)
local domains_body = T.object({
  excludedGlobalEquivalentDomains = T.nullable(T.array(T.number({ integer=true, min=0, max=100 }), { max=100 })),
  equivalentDomains               = T.nullable(T.array(T.array(T.string({ max=256 }), { max=50 }), { max=100 })),
})

-- Organization group create/update body (src/api/core/organizations.rs: GroupRequest)
local group_body = T.object({
  name        = T.string({ max=256 }),
  accessAll   = T.boolean(),
  externalId  = T.nullable(T.string({ max=256 })),
  collections = T.array(collection_access_entry, { max=500 }),
  users       = T.array(T.uuid(), { max=5000 }),
}, { required = { name=true, accessAll=true, collections=true, users=true } })

-- ---------------------------------------------------------------------------
-- Validates the Vaultwarden JWT "iss" claim against the current server's hostname.
-- Vaultwarden sets iss = "https://<configured-base-url>|<suffix>".
-- ngx.var.server_name is evaluated at request time (access phase), not at
-- module-load time, so the closure picks up the live nginx server_name value.
local function vw_iss(suffix)
  return function(v, path)
    if type(v) ~= "string" then return false, path .. " must be a string" end
    local expected = "https://" .. (ngx.var.http_host or "") .. "|" .. suffix
    if v ~= expected then return false, path .. ": unexpected iss" end
    return true
  end
end

-- ---------------------------------------------------------------------------
-- Vaultwarden login token (LoginJwtClaims in auth.rs).
-- Shared by:
--   vw_access_token  — query-param JWT on the WebSocket endpoint
--   vw_auth_header   — Authorization: Bearer header on all authenticated routes
-- Signature verification is Vaultwarden's job; we validate structure + exp.
-- ---------------------------------------------------------------------------
local vw_login_claims = {
  nbf            = T.number({ integer=true }),
  exp            = T.number({ integer=true }),
  iss            = vw_iss("login"),
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
}

-- JWT header: {"typ":"JWT","alg":"RS256"}
local vw_jwt_header = {
  typ = T.string({ enum={ ["JWT"]=true } }),
  alg = T.string({ enum={ ["RS256"]=true } }),
}

local vw_access_token = T.jwt_claims(vw_login_claims, vw_jwt_header)
local vw_auth_header  = T.bearer_jwt(vw_login_claims, vw_jwt_header)

-- ---------------------------------------------------------------------------
-- JWT for the attachment file-download endpoint
-- iss = "https://<host>|file_download"
-- ---------------------------------------------------------------------------
local vw_file_token = T.jwt_claims({
  nbf     = T.number({ integer=true }),
  exp     = T.number({ integer=true }),
  iss     = vw_iss("file_download"),
  sub     = T.uuid(),
  file_id = T.string({ max=64 }),
}, {
  typ = T.string({ enum={ ["JWT"]=true } }),
  alg = T.string({ enum={ ["RS256"]=true } }),
})

-- ---------------------------------------------------------------------------
-- Org API-key bearer token (OrgApiKeyLoginJwtClaims in auth.rs), used only by
-- POST /api/public/organization/import (LDAP/directory-connector sync).
-- Distinct from vw_login_claims: iss suffix is "api.organization", sub is the
-- org API key's own UUID (not a user), client_id = "organization.<org_uuid>".
-- Overrides the default "authorization" header validator on that one route.
-- ---------------------------------------------------------------------------
local vw_org_api_key_header = T.bearer_jwt({
  nbf        = T.number({ integer=true }),
  exp        = T.number({ integer=true }),
  iss        = vw_iss("api.organization"),
  sub        = T.uuid(),
  client_id  = T.string({ max=64, match=[[^organization\.]] .. T.uuid_re .. [[$]] }),
  client_sub = T.uuid(),
  scope      = T.array(T.string({ max=32, enum={ ["api.organization"]=true } }), { max=1 }),
}, {
  typ = T.string({ enum={ ["JWT"]=true } }),
  alg = T.string({ enum={ ["RS256"]=true } }),
})

-- ---------------------------------------------------------------------------
return {
  name    = "vaultwarden",
  mode = "block",   -- flip to "block" after validating against real traffic
  verbose = 2,
  -- Global kill-switch for every opts.required check in this app's schemas
  -- (see types.lua T.object / core.lua). Flip to false as a safety valve if a
  -- newly-added required field starts producing false positives before you
  -- can patch the specific field -- leave true otherwise.
  enforce_required = true,
  -- on_deny fires only in "block" mode.  Requires the ipset to exist:
  --   ipset create waf-blocklist hash:ip timeout 3600
  on_deny = core.ipset_deny_hook("waf-blocklist"),

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
      ["sec-fetch-storage-access"] = T.sec_fetch_storage_access(),
      -- DeviceType enum (libs/common/src/enums/device-type.enum.ts): 0–26
      ["device-type"]            = T.string({ max=2,  match=[[^(?:[0-9]|1[0-9]|2[0-6])$]] }),
      -- Version string: YYYY.M.P  (e.g. 2026.5.1)
      ["bitwarden-client-version"] = T.string({ max=32, match=[[^\d{4}\.\d{1,2}\.\d+$]] }),
      -- Only sent as "1" on prerelease builds; absent on stable
      ["is-prerelease"]          = T.string({ max=1,  enum={ ["1"]=true } }),
      -- Device GUIDs sent by official clients to identify the registered device
      ["device-identifier"]      = T.uuid(),
      ["x-device-identifier"]    = T.uuid(),
      -- Base64url-encoded (not standard base64) email address sent by the web
      -- vault on some requests. Decoded server-side with BASE64URL_NOPAD
      -- (src/api/core/accounts.rs: KnownDevice guard); padding is optional
      -- ("Bitwarden seems to send padded Base64 strings since 2026.2.1").
      ["x-request-email"]        = T.string({ max=256, match=[[^[A-Za-z0-9\-_]*=*$]] }),
      ["bitwarden-package-type"] = T.string({ max=32, enum={
        ["Chrome Extension"]         = true,
        ["Firefox Extension"]        = true,
        ["Opera Extension"]          = true,
        ["Edge Extension"]           = true,
        ["Vivaldi Extension"]        = true,
        ["Safari Extension"]         = true,
        ["Unknown Browser Extension"]= true,
      }}),
      -- When an Authorization header is present it must be a valid, non-expired
      -- Vaultwarden bearer JWT.  Unauthenticated routes that omit the header
      -- are unaffected; the validator only fires when the header is present.
      ["authorization"]          = vw_auth_header,
      ["bitwarden-client-name"]  = T.string({ max=64 }),
    },
  },

  -- Route matching: first match wins, so put more-specific paths before parameterized ones.
  -- Each section name corresponds to a Vaultwarden source file (api/core/ciphers.rs, etc.).
  -- no_body = true  → reject any request body (GET/DELETE endpoints).
  -- json = T.object({...})  → parse and validate JSON body; unknown keys are rejected.
  -- Schema fields are validated when present; add to opts.required = {...} to enforce them.
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
        -- DeviceType enum: 0-26 (matches the device-type header validator below)
        deviceType        = T.nullable(T.string({ max=2, match=[[^(?:[0-9]|1[0-9]|2[0-6])$]] })),
        deviceIdentifier  = T.nullable(T.uuid()),
        deviceName        = nu_sml,
        devicePushToken   = nu_sml,
        twoFactorToken    = T.nullable(T.string({ max=4096 })),  -- remember-me JWT, TOTP, WebAuthn, etc.
        twoFactorProvider = T.nullable(T.string({ max=2, match=[[^(?:[0-9]|10)$]] })),
        twoFactorRemember = T.nullable(T.string({ max=1, match=[[^[01]$]] })),
        authRequest       = T.nullable(T.uuid()),
        -- SSO / OIDC fields (grant_type="authorization_code")
        code              = T.nullable(T.string({ max=1024 })),
        code_verifier     = T.nullable(T.string({ max=256 })),
      }, { required = { grant_type=true } }),
    },

    {
      name         = "prelogin",
      method       = "POST",
      paths        = { [[^/identity/accounts/prelogin$]], [[^/identity/accounts/prelogin/password$]] },
      content_type = "application/json",
      json = T.object({ email = T.email() }, { required = { email=true } }),
    },

    -- Registration: new two-step flow (send-verification-email → finish)
    -- and legacy single-step register.  All three share the identity service.
    -- (src/api/identity.rs: register_verification_email, register_finish, identity_register)
    { name = "register send-email", method = "POST",
      path         = [[^/identity/accounts/register/send-verification-email$]],
      content_type = "application/json",
      json = T.object({
        email = T.email(),
        name  = nu_sml,
      }, { required = { email=true } }) },
    { name = "register finish", method = "POST",
      path         = [[^/identity/accounts/register/finish$]],
      content_type = "application/json",
      json         = register_body },
    { name = "register legacy", method = "POST",
      path         = [[^/identity/accounts/register$]],
      content_type = "application/json",
      json         = register_body },

    -- VAULT SYNC ------------------------------------------------------------

    { name = "tasks",         method = "GET", path = [[^/api/tasks$]],                  no_body = true },
    { name = "sync", method = "GET", path = [[^/api/sync$]], no_body = true,
      query = T.object({ excludeDomains = T.bool_query() }) },
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
      json = share_cipher_body },
    -- Details endpoint: includes org collection membership alongside the cipher
    { name = "cipher details",           method = "GET",    path = "^/api/ciphers/" .. U .. "/details$",         no_body = true },
    -- POST alias for PUT cipher update
    { name = "cipher update-post",       method = "POST",   path = "^/api/ciphers/" .. U .. "$",                 content_type = "application/json", json = cipher_body },
    -- Admin update: org owner/admin may edit any cipher in the org
    { name = "cipher admin update",     methods = { "PUT", "POST" }, path = "^/api/ciphers/" .. U .. "/admin$",  content_type = "application/json", json = cipher_body },
    -- Partial update: folderId + favorite only (does not touch encrypted data)
    { name = "cipher partial update",   methods = { "PUT", "POST" }, path = "^/api/ciphers/" .. U .. "/partial$", content_type = "application/json", json = cipher_partial_body },
    -- Collection assignment variants (v2 returns the updated cipher body; v1 does not)
    { name = "cipher collections-v2",   methods = { "PUT", "POST" }, path = "^/api/ciphers/" .. U .. "/collections_v2$",     content_type = "application/json", json = cipher_collections_body },
    { name = "cipher collections",      methods = { "PUT", "POST" }, path = "^/api/ciphers/" .. U .. "/collections$",        content_type = "application/json", json = cipher_collections_body },
    { name = "cipher collections-admin",methods = { "PUT", "POST" }, path = "^/api/ciphers/" .. U .. "/collections-admin$",  content_type = "application/json", json = cipher_collections_body },
    -- Bulk collection assignment across multiple ciphers at once (org vault view)
    -- (src/api/core/organizations.rs: BulkCollectionsData — all fields required)
    { name = "ciphers bulk-collections", method = "POST", path = [[^/api/ciphers/bulk-collections$]],
      content_type = "application/json",
      json = T.object({
        organizationId    = T.uuid(),
        cipherIds         = T.array(T.uuid(), { max=2000 }),
        collectionIds     = T.array(T.uuid(), { max=200 }),
        removeCollections = T.boolean(),
      }, { required = { organizationId=true, cipherIds=true, collectionIds=true, removeCollections=true } }) },
    -- Soft-delete POST alias (clients may use POST or PUT for idempotency)
    { name = "cipher soft-delete-post",      method = "POST",   path = "^/api/ciphers/" .. U .. "/delete$",         no_body = true },
    -- Admin soft-delete (org admin can trash any cipher)
    { name = "cipher admin soft-delete",    methods = { "PUT", "POST" }, path = "^/api/ciphers/" .. U .. "/delete-admin$", no_body = true },
    -- Admin hard-delete
    { name = "cipher admin delete",          method = "DELETE", path = "^/api/ciphers/" .. U .. "/admin$",           no_body = true },
    -- Admin restore single cipher from trash
    { name = "cipher admin restore",         method = "PUT",    path = "^/api/ciphers/" .. U .. "/restore-admin$",   no_body = true },
    -- Individual archive / unarchive (separate from the bulk PUT /ciphers/archive)
    { name = "cipher archive",               method = "PUT",    path = "^/api/ciphers/" .. U .. "/archive$",         no_body = true },
    { name = "cipher unarchive",             method = "PUT",    path = "^/api/ciphers/" .. U .. "/unarchive$",       no_body = true },
    { name = "ciphers archive",   method = "PUT",  path = [[^/api/ciphers/archive$]],   content_type = "application/json", json = cipher_ids_body },
    { name = "ciphers unarchive", method = "PUT",  path = [[^/api/ciphers/unarchive$]], content_type = "application/json", json = cipher_ids_body },
    { name = "ciphers import",    method = "POST", path = [[^/api/ciphers/import$]],
      content_type = "application/json",
      -- App default (5MB) doesn't actually fit a schema-max (5000-cipher)
      -- import once each cipher item is more than trivially small (found via
      -- gen.lua's array-boundary test hitting a real body-size deny at
      -- exactly the declared max, not the array-length check).
      max_body = 10 * 1024 * 1024,
      json = T.object({
        ciphers = T.array(cipher_body, { max = 5000 }),
        folders = T.array(T.object({
          id   = nu_uuid,
          name = enc,
        }), { max = 1000 }),
        folderRelationships = T.array(T.object({
          key   = T.number({ integer=true, min=0, max=4999 }),
          value = T.number({ integer=true, min=0, max=999 }),
        }), { max = 5000 }),
      }) },
    -- Org-scoped import (distinct from personal-vault "ciphers import" above):
    -- collections use the full org-collection shape, plus a cipher<->collection
    -- index-pair relationship list instead of a folder one.
    -- (src/api/core/organizations.rs: ImportData; org_id via ?organizationId=)
    { name = "cipher import-organization", method = "POST", path = [[^/api/ciphers/import-organization$]],
      content_type = "application/json",
      query = T.object({ organizationId = T.uuid() }, { required = { organizationId=true } }),
      -- Same max_body bump as "ciphers import" above, same reason.
      max_body = 10 * 1024 * 1024,
      json = T.object({
        ciphers     = T.array(cipher_body, { max = 5000 }),
        collections = T.array(full_collection_body, { max = 1000 }),
        collectionRelationships = T.array(T.object({
          key   = T.number({ integer=true, min=0, max=4999 }),
          value = T.number({ integer=true, min=0, max=999 }),
        }), { max = 5000 }),
      }) },
    { name = "ciphers bulk-delete",method = "DELETE", path = [[^/api/ciphers$]],           content_type = "application/json", json = cipher_ids_body },
    -- Org-admin cipher create: same body shape as cipher share
    { name = "cipher admin create", method = "POST", path = [[^/api/ciphers/admin$]],
      content_type = "application/json",
      json = share_cipher_body },
    -- Org cipher list: query param only, no body
    { name = "org cipher details", method = "GET", path = [[^/api/ciphers/organization-details$]],
      query = T.object({ organizationId = T.uuid() }), no_body = true },
    -- POST alias for cipher create (some older clients use /ciphers/create).
    -- Same ShareCipherData wrapper as "cipher share"/"cipher admin create",
    -- not a bare cipher_body (src/api/core/ciphers.rs: post_ciphers_create).
    { name = "cipher create-post", method = "POST", path = [[^/api/ciphers/create$]],
      content_type = "application/json",
      json = share_cipher_body },
    -- Bulk share: re-encrypts and moves multiple ciphers into org collections at once
    { name = "ciphers share-bulk",   method = "PUT",  path = [[^/api/ciphers/share$]],
      content_type = "application/json",
      json = T.object({
        ciphers       = T.array(cipher_body, { max=2000 }),
        collectionIds = T.array(T.uuid(), { max=200 }),
      }) },
    -- Bulk soft-delete aliases
    { name = "ciphers soft-delete-post",      method = "POST",   path = [[^/api/ciphers/delete$]],         content_type = "application/json", json = cipher_ids_body },
    { name = "ciphers soft-delete-put",       method = "PUT",    path = [[^/api/ciphers/delete$]],         content_type = "application/json", json = cipher_ids_body },
    -- Admin bulk hard-delete (DELETE /ciphers/admin and its POST/PUT aliases)
    { name = "ciphers admin bulk-delete",     method = "DELETE", path = [[^/api/ciphers/admin$]],          content_type = "application/json", json = cipher_ids_body },
    { name = "ciphers admin bulk-delete-post",method = "POST",   path = [[^/api/ciphers/delete-admin$]],   content_type = "application/json", json = cipher_ids_body },
    { name = "ciphers admin bulk-delete-put", method = "PUT",    path = [[^/api/ciphers/delete-admin$]],   content_type = "application/json", json = cipher_ids_body },
    -- Bulk restore from trash
    { name = "ciphers restore-bulk",       method = "PUT", path = [[^/api/ciphers/restore$]],       content_type = "application/json", json = cipher_ids_body },
    { name = "ciphers admin restore-bulk", method = "PUT", path = [[^/api/ciphers/restore-admin$]], content_type = "application/json", json = cipher_ids_body },
    -- Move ciphers to a folder (POST and PUT both supported)
    { name = "ciphers move", methods = { "POST", "PUT" }, path = [[^/api/ciphers/move$]],
      content_type = "application/json",
      json = T.object({
        folderId = nu_uuid_or_empty,
        ids      = T.array(T.uuid(), { max=2000 }),
      }) },
    -- Purge vault: body authenticates the action; optional ?organizationId=<uuid> for org vault
    { name = "ciphers purge", method = "POST", path = [[^/api/ciphers/purge$]],
      content_type = "application/json", json = password_or_otp,
      query = T.object({ organizationId = T.nullable(T.uuid()) }) },

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
    -- Legacy v1 upload: single multipart POST without a pre-signed URL step
    { name = "attachment create-v1",         method = "POST",   path = "^/api/ciphers/" .. U .. "/attachment$",                              content_type = "multipart/form-data" },
    -- Admin upload: org admin attaches a file to any cipher in the org
    { name = "attachment create-admin",      method = "POST",   path = "^/api/ciphers/" .. U .. "/attachment-admin$",                        content_type = "multipart/form-data" },
    -- Re-encrypt an attachment when sharing a cipher into an org collection
    { name = "attachment share",             method = "POST",   path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "/share$",        content_type = "multipart/form-data" },
    -- Soft-delete POST alias and admin variants
    { name = "attachment delete-post",       method = "POST",   path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "/delete$",       no_body = true },
    { name = "attachment delete-admin-post", method = "POST",   path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "/delete-admin$", no_body = true },
    { name = "attachment admin-delete",      method = "DELETE", path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "/admin$",        no_body = true },

    -- FOLDERS ---------------------------------------------------------------

    { name = "folder list",   method = "GET",    path = [[^/api/folders$]],           no_body = true },
    { name = "folder create", method = "POST",   path = [[^/api/folders$]],           content_type = "application/json", json = folder_body },
    { name = "folder get",    method = "GET",    path = "^/api/folders/" .. U .. "$", no_body = true },
    { name = "folder update", method = "PUT",    path = "^/api/folders/" .. U .. "$", content_type = "application/json", json = folder_body },
    -- POST alias for PUT folder update (src/api/core/folders.rs: post_folder delegates to put_folder)
    { name = "folder update-post", method = "POST", path = "^/api/folders/" .. U .. "$", content_type = "application/json", json = folder_body },
    { name = "folder delete", method = "DELETE", path = "^/api/folders/" .. U .. "$", no_body = true },
    -- POST alias for DELETE folder delete
    { name = "folder delete-post", method = "POST", path = "^/api/folders/" .. U .. "/delete$", no_body = true },

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
    -- Send access IDs are base64url-encoded UUID bytes (22 chars), not standard UUIDs.
    { name = "send access",          method = "POST",   path = [[^/api/sends/access/[^/]{1,32}$]],
      content_type = "application/json", json = T.object({ password = T.nullable(sml) }) },
    -- Legacy v1 file send: single multipart POST (no pre-signed URL step)
    { name = "send create-file-v1",  method = "POST",   path = [[^/api/sends/file$]],
      content_type = "multipart/form-data" },
    -- File access: retrieve a file attachment from a Send (same password body as send access)
    { name = "send access-file",     method = "POST",   path = "^/api/sends/" .. U .. "/access/file/" .. FILEID .. "$",
      content_type = "application/json", json = T.object({ password = T.nullable(sml) }) },
    -- Token-authenticated file download (token is a short-lived signed JWT)
    { name = "send file-download",   method = "GET",    path = "^/api/sends/" .. U .. "/" .. FILEID .. "$",
      query = T.object({ t = T.string({ max=4096 }) }), no_body = true },
    -- Remove password protection from a Send
    { name = "send remove-password", method = "PUT",    path = "^/api/sends/" .. U .. "/remove-password$", no_body = true },

    -- ACCOUNT MANAGEMENT ----------------------------------------------------

    -- Profile & avatar
    { name = "profile get",        method = "GET",    path = [[^/api/accounts/profile$]],           no_body = true },
    { name = "profile update", methods = { "PUT", "POST" }, path = [[^/api/accounts/profile$]],
      content_type = "application/json",
      json = T.object({ name = T.string({ max=50 }), masterPasswordHint = nu_sml }) },
    { name = "avatar update", method = "PUT", path = [[^/api/accounts/avatar$]],
      content_type = "application/json",
      json = T.object({ avatarColor = T.nullable(T.string({ max=7, match=[[^#[0-9a-fA-F]{6}$]] })) }) },

    -- Password & KDF
    -- Rust: ChangePassData (accounts.rs:502) -- all four fields non-Option.
    { name = "password change", method = "POST", path = [[^/api/accounts/password$]],
      content_type = "application/json",
      json = T.object({
        masterPasswordHash    = med,
        newMasterPasswordHash = med,
        masterPasswordHint    = T.nullable(sml),
        key                   = enc,
      }, { required = { masterPasswordHash=true, newMasterPasswordHash=true, key=true } }) },
    -- Rust: ChangeKdfData (accounts.rs:601) -- masterPasswordHash/newMasterPasswordHash/
    -- key/authenticationData/unlockData are all non-Option, as are every field of
    -- AuthenticationData (accounts.rs:585) and UnlockData (accounts.rs:593).
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
        }, { required = { salt=true, kdf=true, masterPasswordAuthenticationHash=true } }),
        unlockData = T.object({
          salt                    = sml,
          kdf                     = kdf_data,
          masterKeyWrappedUserKey = enc,
        }, { required = { salt=true, kdf=true, masterKeyWrappedUserKey=true } }),
      }, { required = { masterPasswordHash=true, newMasterPasswordHash=true, key=true,
                         authenticationData=true, unlockData=true } }) },
    -- Keys
    -- /accounts/key does not exist in Vaultwarden; kept to avoid 404-before-proxy on old clients
    { name = "key update",  method = "POST", path = [[^/api/accounts/key$]],  content_type = "application/json" },
    { name = "keys update", method = "POST", path = [[^/api/accounts/keys$]],
      content_type = "application/json",
      json = asym_keys_body },

    -- Verification
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

    -- Email & account lifecycle
    { name = "delete account",     methods = { "DELETE", "POST" }, path = [[^/api/accounts(/delete)?$]],
      content_type = "application/json",
      json = password_or_otp },
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
        -- Rust: NumberOrString (ChangeEmailData.token); generated as a 6-digit
        -- code (crypto::generate_email_token(6)) but clients may send it as
        -- either a JSON number or a numeric string.
        token                 = T.number_or_string({ integer=true, min=0, max=999999 }),
      }) },
    -- Set password: used after SSO registration / invite with no prior password
    -- kdf fields are top-level (flattened from KDFData struct)
    -- Rust: SetPasswordData (accounts.rs:121) -- kdf/kdfIterations (via the
    -- flattened KDFData), key, and masterPasswordHash are all non-Option.
    { name = "set-password", method = "POST", path = [[^/api/accounts/set-password$]],
      content_type = "application/json",
      json = T.object({
        kdf             = T.number({ integer=true, min=0, max=1 }),
        kdfIterations   = T.number({ integer=true, min=1, max=2000000 }),
        kdfMemory       = nu_kdf_memory,
        kdfParallelism  = nu_kdf_parallelism,
        key             = enc,
        keys            = T.nullable(asym_keys_body),
        masterPasswordHash = med,
        masterPasswordHint = T.nullable(sml),
        orgIdentifier      = T.nullable(T.string({ max=256 })),
      }, { required = { kdf=true, kdfIterations=true, key=true, masterPasswordHash=true } }) },

    -- ---------------------------------------------------------------------------
    -- Key rotation (heavyweight — re-encrypts all vault data)
    -- ---------------------------------------------------------------------------
    -- Account key rotation: replaces all ciphers/folders/sends with re-encrypted versions.
    -- Schema covers both the Vaultwarden 1.36.0 fields and the newer client fields that
    -- the server silently ignores (passkeyUnlockData, deviceKeyUnlockData, publicKeyEncryptionKeyPair,
    -- signatureKeyPair, securityState). T.object rejects unknown keys, so we must include them.
    { name = "rotate-keys", method = "POST", path = [[^/api/accounts/key-management/rotate-user-account-keys$]],
      content_type = "application/json",
      -- Same max_body bump as "ciphers import" above, same reason - this
      -- route's accountData.ciphers carries the same 5000-max cipher_body array.
      max_body = 10 * 1024 * 1024,
      json = T.object({
        -- Hash of the current master key used to authenticate the rotation
        oldMasterKeyAuthenticationHash = sml,

        accountUnlockData = T.object({
          masterPasswordUnlockData = T.object({
            kdfType                     = T.number({ integer=true, min=0, max=1 }),
            kdfIterations               = T.number({ integer=true, min=1, max=2000000 }),
            kdfMemory                   = nu_kdf_memory,
            kdfParallelism              = nu_kdf_parallelism,
            email                       = T.email(),
            masterKeyAuthenticationHash = sml,
            masterKeyEncryptedUserKey   = enc,
            masterPasswordHint          = T.nullable(sml),  -- client sends; server 1.36.0 ignores
          }),
          emergencyAccessUnlockData = T.array(T.object({
            id           = T.uuid(),
            type         = T.number({ integer=true, min=0, max=1 }),
            waitTimeDays = T.number({ integer=true, min=1, max=90 }),
            keyEncrypted = nu_enc,
          }), { max=200 }),
          organizationAccountRecoveryUnlockData = T.array(T.object({
            organizationId        = T.uuid(),
            resetPasswordKey      = nu_enc,
            masterPasswordHash    = T.nullable(med),
            otp                   = T.nullable(T.string({ max=16 })),
            authRequestAccessCode = T.nullable(T.string({ max=128 })),
          }), { max=200 }),
          -- Newer fields the client sends; Vaultwarden 1.36.0 ignores both
          passkeyUnlockData = T.nullable(T.array(T.object({
            id                 = T.string({ max=512 }),
            encryptedPublicKey = enc,
            encryptedUserKey   = enc,
          }), { max=50 })),
          deviceKeyUnlockData = T.nullable(T.array(T.object({
            encryptedPublicKey = nu_enc,
            encryptedUserKey   = nu_enc,
          }), { max=50 })),
        }),

        accountKeys = T.object({
          -- Deprecated in newer clients but still included in every request
          userKeyEncryptedAccountPrivateKey = nu_enc,
          accountPublicKey                  = T.nullable(T.string({ max=4096 })),
          -- Newer key-pair fields; Vaultwarden 1.36.0 ignores all three
          publicKeyEncryptionKeyPair = T.nullable(T.object({
            wrappedPrivateKey = enc,
            publicKey         = T.string({ max=4096 }),
            signedPublicKey   = T.nullable(T.string({ max=8192 })),
          })),
          signatureKeyPair = T.nullable(T.object({
            signatureAlgorithm = T.string({ max=64 }),
            wrappedSigningKey  = enc,
            verifyingKey       = T.string({ max=512 }),
          })),
          securityState = T.nullable(T.object({
            securityState   = T.string({ max=8192 }),
            securityVersion = T.number({ integer=true, min=0, max=9999 }),
          })),
        }),

        accountData = T.object({
          -- cipher_body already contains id as nu_uuid; rotation always populates it
          ciphers = T.array(cipher_body, { max=5000 }),
          -- Bitwarden bug #8453 can inject null items; Vaultwarden skips them
          folders = T.array(T.nullable(T.object({
            id   = nu_uuid,
            name = enc,
          })), { max=1000 }),
          -- send_body already contains id as nu_uuid
          sends = T.array(send_body, { max=5000 }),
        }),
      }) },
    -- Account deletion recovery & password hint
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
    -- API key & OTP
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
    { name = "2fa get-webauthn-challenge", method = "POST", path = [[^/api/two-factor/get-webauthn-challenge$]], content_type = "application/json", json = password_or_otp },
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
        -- Rust: NumberOrString (DisableTwoFactorData.type). TwoFactorType enum
        -- (db/models/two_factor.rs) user-facing range is 0-8; 1000+/2000 are
        -- internal challenge/protected-action markers, not client-sent values.
        type               = T.number_or_string({ integer=true, min=0, max=8 }),
      }) },
    { name = "2fa device-verification-settings", method = "GET", path = [[^/api/two-factor/get-device-verification-settings$]], no_body = true },
    -- TOTP (authenticator app)
    { name = "2fa totp activate", methods = { "POST", "PUT" }, path = [[^/api/two-factor/authenticator$]],
      content_type = "application/json",
      json = T.object({
        key                = T.string({ max=256 }),
        -- Rust: NumberOrString (EnableAuthenticatorData.token) -- the 6-digit
        -- TOTP code from the authenticator app.
        token              = T.number_or_string({ integer=true, min=0, max=999999 }),
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },
    { name = "2fa totp delete",   method = "DELETE", path = [[^/api/two-factor/authenticator$]],
      content_type = "application/json",
      json = T.object({
        key                = T.string({ max=256 }),
        masterPasswordHash = med,
        -- Rust: NumberOrString (DisableAuthenticatorData.type). Same
        -- TwoFactorType enum as "2fa disable" above -- 0-8, not 0-255.
        type               = T.number_or_string({ integer=true, min=0, max=8 }),
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
        -- Rust: NumberOrString (EnableWebauthnData.id, 1..5)
        id   = T.number_or_string({ integer=true, min=1, max=5 }),
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
        -- Rust: NumberOrString (DeleteU2FData.id)
        id                 = T.number_or_string({ integer=true, min=1, max=5 }),
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },

    -- ORGANIZATIONS & COLLECTIONS -------------------------------------------

    { name = "org list",   method = "GET",  path = [[^/api/organizations$]], no_body = true },
    { name = "org get",    method = "GET",  path = "^/api/organizations/" .. U .. "$", no_body = true },
    { name = "org update", methods = { "PUT", "POST" }, path = "^/api/organizations/" .. U .. "$",
      content_type = "application/json",
      json = T.object({ billingEmail = T.email(), name = T.string({ max=256 }) }, { required = { billingEmail=true, name=true } }) },
    { name = "org delete", method = "DELETE", path = "^/api/organizations/" .. U .. "$",
      content_type = "application/json", json = password_or_otp },
    { name = "org delete-post", method = "POST", path = "^/api/organizations/" .. U .. "/delete$",
      content_type = "application/json", json = password_or_otp },
    { name = "org leave", method = "POST", path = "^/api/organizations/" .. U .. "/leave$", no_body = true },
    -- Auto-enroll status: identifier may be a UUID or a special SSO string
    { name = "org auto-enroll-status", method = "GET", path = [[^/api/organizations/[^/]+/auto-enroll-status$]], no_body = true },
    { name = "org keys", method = "POST", path = "^/api/organizations/" .. U .. "/keys$",
      content_type = "application/json",
      json = asym_keys_body },
    -- Org CLI API-key retrieval / rotation (same auth-verification body as the
    -- personal-account api-key/rotate-api-key routes above)
    { name = "org api-key",        method = "POST", path = "^/api/organizations/" .. U .. "/api-key$",
      content_type = "application/json", json = password_or_otp },
    { name = "org rotate-api-key", method = "POST", path = "^/api/organizations/" .. U .. "/rotate-api-key$",
      content_type = "application/json", json = password_or_otp },
    -- SSO domain stub: always returns a dummy value
    { name = "org sso-verified", method = "POST", path = [[^/api/organizations/domain/sso/verified$]], no_body = true },
    { name = "org create", method = "POST", path = [[^/api/organizations$]],
      content_type = "application/json",
      json = T.object({
        billingEmail   = T.email(),
        collectionName = enc,
        key            = enc,
        name           = T.string({ max=256 }),
        -- Rust: NumberOrString (OrgData.plan_type) -- ignored server-side
        -- (self-hosted always uses the same plan) but still type-checked.
        planType       = T.nullable(T.number_or_string({ integer=true, min=0, max=100 })),
        keys = keys_data,
      }, { required = { billingEmail=true, collectionName=true, key=true, name=true } }) },
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
    { name = "org groups",              method = "GET",    path = "^/api/organizations/" .. U .. "/groups$",                no_body = true },
    -- Groups list with full collection-access detail
    { name = "org groups details",      method = "GET",    path = "^/api/organizations/" .. U .. "/groups/details$",         no_body = true },
    -- Group create
    { name = "org group create",        method = "POST",   path = "^/api/organizations/" .. U .. "/groups$",                 content_type = "application/json", json = group_body },
    -- Group update: both PUT and POST are supported
    { name = "org group update",       methods = { "PUT", "POST" }, path = "^/api/organizations/" .. U .. "/groups/" .. U .. "$", content_type = "application/json", json = group_body },
    -- Single group GET variants
    { name = "org group get",           method = "GET",    path = "^/api/organizations/" .. U .. "/groups/" .. U .. "$",          no_body = true },
    { name = "org group get-details",   method = "GET",    path = "^/api/organizations/" .. U .. "/groups/" .. U .. "/details$",   no_body = true },
    -- Group delete (DELETE and POST alias)
    { name = "org group delete",        method = "DELETE", path = "^/api/organizations/" .. U .. "/groups/" .. U .. "$",          no_body = true },
    { name = "org group delete-post",   method = "POST",   path = "^/api/organizations/" .. U .. "/groups/" .. U .. "/delete$",   no_body = true },
    -- Bulk group delete
    { name = "org groups bulk-delete",  method = "DELETE", path = "^/api/organizations/" .. U .. "/groups$",                 content_type = "application/json", json = bulk_uuid_ids },
    -- Group member management: body is a raw JSON array of membership UUIDs
    { name = "org group members get",   method = "GET",    path = "^/api/organizations/" .. U .. "/groups/" .. U .. "/users$",    no_body = true },
    { name = "org group members set",   method = "PUT",    path = "^/api/organizations/" .. U .. "/groups/" .. U .. "/users$",    content_type = "application/json", json = T.array(T.uuid(), { max=5000 }) },
    -- Remove a single member from a group
    { name = "org group remove-member", method = "POST",   path = "^/api/organizations/" .. U .. "/groups/" .. U .. "/delete-user/" .. U .. "$", no_body = true },
    -- Org user management
    { name = "org users", method = "GET", path = "^/api/organizations/" .. U .. "/users$", no_body = true,
      query = T.object({
        includeCollections = T.bool_query(),
        includeGroups      = T.bool_query(),
      }) },
    { name = "org user mini-details", method = "GET", path = "^/api/organizations/" .. U .. "/users/mini-details$", no_body = true },
    { name = "org user get",     method = "GET", path = "^/api/organizations/" .. U .. "/users/" .. U .. "$", no_body = true,
      query = T.object({
        includeCollections = T.bool_query(),
        includeGroups      = T.bool_query(),
      }) },
    { name = "org user update",  methods = { "PUT", "POST" }, path = "^/api/organizations/" .. U .. "/users/" .. U .. "$",
      content_type = "application/json",
      json = T.object({
        -- Rust: NumberOrString (EditUserData.type)
        type        = T.number_or_string({ integer=true, min=0, max=4 }),
        collections = T.nullable(T.array(collection_access_entry, { max=500 })),
        groups      = T.nullable(T.array(T.uuid(), { max=500 })),
        permissions = T.nullable(permissions_body),
      }) },
    { name = "org user delete",  method = "DELETE", path = "^/api/organizations/" .. U .. "/users/" .. U .. "$", no_body = true },
    { name = "org users invite",  method = "POST", path = "^/api/organizations/" .. U .. "/users/invite$",
      content_type = "application/json",
      json = T.object({
        emails      = T.array(T.email(), { max=200 }),
        groups      = T.array(T.uuid(), { max=200 }),
        -- Rust: NumberOrString (InviteData.type)
        type        = T.number_or_string({ integer=true, min=0, max=4 }),
        collections = T.nullable(T.array(collection_access_entry, { max=500 })),
        permissions = T.nullable(permissions_body),
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

    -- Revoke / restore org membership
    { name = "org user revoke",        method = "PUT", path = "^/api/organizations/" .. U .. "/users/" .. U .. "/revoke$",  no_body = true },
    -- Bulk revoke: ids=null means all confirmed members
    { name = "org users revoke-bulk",  method = "PUT", path = "^/api/organizations/" .. U .. "/users/revoke$",
      content_type = "application/json",
      json = T.object({ ids = T.nullable(T.array(T.uuid(), { max=2000 })) }) },
    { name = "org user restore",       method = "PUT", path = "^/api/organizations/" .. U .. "/users/" .. U .. "/restore$", no_body = true },
    { name = "org users restore-bulk", method = "PUT", path = "^/api/organizations/" .. U .. "/users/restore$",
      content_type = "application/json", json = bulk_uuid_ids },

    -- Account recovery / reset-password
    { name = "org user reset-pw-details", method = "GET",
      path = "^/api/organizations/" .. U .. "/users/" .. U .. "/reset-password-details$", no_body = true },
    { name = "org user reset-password", method = "PUT",
      path = "^/api/organizations/" .. U .. "/users/" .. U .. "/reset-password$",
      content_type = "application/json",
      json = T.object({
        newMasterPasswordHash = med,
        key                   = enc,
      }) },
    -- Member enrolls in or withdraws from admin account recovery
    { name = "org user reset-pw-enrollment", method = "PUT",
      path = "^/api/organizations/" .. U .. "/users/" .. U .. "/reset-password-enrollment$",
      content_type = "application/json",
      json = T.object({
        resetPasswordKey   = nu_enc,
        masterPasswordHash = T.nullable(med),
        otp                = T.nullable(T.string({ max=16 })),
      }) },

    -- Org policies
    { name = "org policies list",  method = "GET", path = "^/api/organizations/" .. U .. "/policies$",        no_body = true },
    -- Token-based lookup: used during invite acceptance (unauthenticated)
    { name = "org policies token", method = "GET", path = "^/api/organizations/" .. U .. "/policies/token$",
      query = T.object({ token = T.string({ max=4096 }) }), no_body = true },
    -- Vaultwarden uses a fixed dummy UUID for the SSO org master-password policy
    { name = "org policy master-pw-sso", method = "GET",
      path = [[^/api/organizations/00000000-01dc-01dc-01dc-000000000000/policies/master-password$]], no_body = true },
    { name = "org policy master-pw", method = "GET",
      path = "^/api/organizations/" .. U .. "/policies/master-password$", no_body = true },
    -- Policy GET/PUT by integer type (0–11 in current Vaultwarden; [0-9]{1,3} gives headroom)
    { name = "org policy get",     method = "GET", path = "^/api/organizations/" .. U .. "/policies/[0-9]{1,3}$", no_body = true },
    { name = "org policy update",  method = "PUT", path = "^/api/organizations/" .. U .. "/policies/[0-9]{1,3}$",
      content_type = "application/json",
      json = T.object({
        enabled = T.boolean(),
        data    = T.nullable(T.any()),  -- shape varies by policy type
      }) },
    { name = "org policy update-vnext", method = "PUT", path = "^/api/organizations/" .. U .. "/policies/[0-9]{1,3}/vnext$",
      content_type = "application/json",
      json = T.object({
        policy = T.object({
          enabled = T.boolean(),
          data    = T.nullable(T.any()),
        }),
      }) },

    -- Billing stubs (Vaultwarden always returns empty/dummy data for self-hosted)
    { name = "org billing metadata",       method = "GET", path = "^/api/organizations/" .. U .. "/billing/metadata$",                no_body = true },
    { name = "org billing warnings",       method = "GET", path = "^/api/organizations/" .. U .. "/billing/vnext/warnings$",          no_body = true },
    { name = "org billing self-host-meta", method = "GET", path = "^/api/organizations/" .. U .. "/billing/vnext/self-host/metadata$", no_body = true },
    -- Personal (cloud-only) billing subscription: not implemented server-side at all,
    -- Vaultwarden's api_not_found catcher 404s it; mobile clients probe it regardless.
    { name = "account billing subscription", method = "GET", path = [[^/api/account/billing/vnext/subscription$]], no_body = true },

    -- Org public key (GET /public-key and backward-compat GET /keys alias)
    { name = "org public-key", method = "GET", path = "^/api/organizations/" .. U .. "/public-key$", no_body = true },
    { name = "org keys-get",   method = "GET", path = "^/api/organizations/" .. U .. "/keys$",       no_body = true },

    -- Vault export
    { name = "org export", method = "GET", path = "^/api/organizations/" .. U .. "/export$", no_body = true },

    -- Plans stub (self-hosted Vaultwarden returns free-plan data)
    { name = "plans", method = "GET", path = [[^/api/plans$]], no_body = true },

    -- EVENT LOG (audit trail) ------------------------------------------------
    -- (src/api/core/events.rs) start/end are ISO8601 date strings; continuationToken
    -- is an opaque pagination cursor, not a UUID.
    { name = "events org",      method = "GET", path = "^/api/organizations/" .. U .. "/events$", no_body = true,
      query = T.object({
        start              = T.iso8601(),
        ["end"]            = T.iso8601(),
        continuationToken  = T.nullable(T.string({ max=1024 })),
      }, { required = { start=true, ["end"]=true } }) },
    { name = "events cipher",   method = "GET", path = "^/api/ciphers/" .. U .. "/events$", no_body = true,
      query = T.object({
        start              = T.iso8601(),
        ["end"]            = T.iso8601(),
        continuationToken  = T.nullable(T.string({ max=1024 })),
      }, { required = { start=true, ["end"]=true } }) },
    { name = "events org-user", method = "GET", path = "^/api/organizations/" .. U .. "/users/" .. U .. "/events$", no_body = true,
      query = T.object({
        start              = T.iso8601(),
        ["end"]            = T.iso8601(),
        continuationToken  = T.nullable(T.string({ max=1024 })),
      }, { required = { start=true, ["end"]=true } }) },

    -- EMERGENCY ACCESS ------------------------------------------------------

    { name = "emergency trusted", method = "GET", path = [[^/api/emergency-access/trusted$]], no_body = true },
    { name = "emergency granted", method = "GET", path = [[^/api/emergency-access/granted$]], no_body = true },
    { name = "emergency invite",  method = "POST", path = [[^/api/emergency-access/invite$]],
      content_type = "application/json",
      json = T.object({
        email        = T.email(),
        -- Rust: NumberOrString (EmergencyAccessInviteData.type)
        type         = T.number_or_string({ integer=true, min=0, max=1 }),
        waitTimeDays = T.number({ integer=true, min=1, max=90 }),
      }, { required = { email=true, type=true, waitTimeDays=true } }) },
    { name = "emergency get",     method = "GET",    path = "^/api/emergency-access/" .. U .. "$",                no_body = true },
    { name = "emergency update",  methods = { "PUT", "POST" }, path = "^/api/emergency-access/" .. U .. "$",
      content_type = "application/json",
      json = T.object({
        -- Rust: NumberOrString (EmergencyAccessUpdateData.type)
        type         = T.number_or_string({ integer=true, min=0, max=1 }),
        waitTimeDays = T.number({ integer=true, min=1, max=90 }),
        keyEncrypted = nu_enc,
      }, { required = { type=true, waitTimeDays=true } }) },
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

    -- PUBLIC API (LDAP / directory-connector sync) ---------------------------
    -- Authenticated with a distinct org-API-key bearer JWT (vw_org_api_key_header),
    -- not the standard user login JWT — overrides the default "authorization"
    -- header validator for this route only.
    -- (src/api/core/public.rs: ldap_import / OrgImportData)
    { name = "public org import", method = "POST", path = [[^/public/organization/import$]],
      content_type = "application/json",
      headers = { authorization = vw_org_api_key_header },
      json = T.object({
        groups = T.array(T.object({
          name               = T.string({ max=256 }),
          externalId         = T.string({ max=256 }),
          memberExternalIds  = T.array(T.string({ max=256 }), { max=5000 }),
        }), { max=1000 }),
        members = T.array(T.object({
          email      = T.email(),
          externalId = T.string({ max=256 }),
          deleted    = T.boolean(),
        }), { max=5000 }),
        overwriteExisting = T.boolean(),
      }, { required = { groups=true, members=true, overwriteExisting=true } }) },

    -- SETTINGS --------------------------------------------------------------

    { name = "domains get",    method = "GET", path = [[^/api/settings/domains$]], no_body = true },
    { name = "domains update", method = "PUT",  path = [[^/api/settings/domains$]], content_type = "application/json", json = domains_body },
    -- POST alias (same handler as PUT)
    { name = "domains post",   method = "POST", path = [[^/api/settings/domains$]], content_type = "application/json", json = domains_body },

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
    -- Unauthenticated WS subscription (Send access views, login-with-device
    -- approval push). token here is an opaque per-subscription string, not a JWT.
    { name = "notifications anonymous-hub", method = "GET", path = [[^/notifications/anonymous-hub$]],
      query = T.object({ token = T.string({ max=256 }) }, { required = { token=true } }), no_body = true },

    -- EVENT COLLECTION (client-side audit logging) ---------------------------
    -- Separate top-level mount point (/events), not under /api.
    -- (src/api/core/events.rs: EventCollection — type/date required, ids optional)
    { name = "events collect", method = "POST", path = [[^/events/collect$]],
      content_type = "application/json",
      json = T.array(T.object({
        type           = T.number({ integer=true, min=0, max=2000 }),
        date           = T.iso8601(),
        cipherId       = nu_uuid,
        organizationId = nu_uuid,
      }, { required = { type=true, date=true } }), { max=1000 }) },

    -- MISCELLANEOUS ---------------------------------------------------------

    { name = "alive",       method = "GET", path = [[^/api/alive$]],   no_body = true },
    { name = "now",         method = "GET", path = [[^/api/now$]],     no_body = true },
    { name = "version",     method = "GET", path = [[^/api/version$]], no_body = true },
    -- HIBP proxied breach lookup: username is an email address (max 320 chars per RFC 5321)
    { name = "hibp-breach", method = "GET", path = [[^/api/hibp/breach$]],
      query = T.object({ username = T.string({ max=320 }) }), no_body = true },

    -- ADMIN PANEL -----------------------------------------------------------
    -- Routes are listed most-specific-first so the parameterized catch-all
    -- for /admin/users/<uuid> does not shadow the named sub-paths.

    -- Landing page (GET) and form login (POST)
    { name = "admin page",  method = "GET",  path = [[^/admin/?$]], no_body = true },
    { name = "admin login", method = "POST", path = [[^/admin/?$]],
      content_type = "application/x-www-form-urlencoded",
      form = T.object({
        token    = T.string({ max = 1024 }),
        redirect = T.nullable(T.string({ max = 1024 })),
      }, { required = { token=true } }),
    },

    { name = "admin logout", method = "GET", path = [[^/admin/logout$]], no_body = true },

    { name = "admin invite",    method = "POST", path = [[^/admin/invite$]],
      content_type = "application/json",
      json = T.object({ email = T.email() }),
    },
    { name = "admin test smtp", method = "POST", path = [[^/admin/test/smtp$]],
      content_type = "application/json",
      json = T.object({ email = T.email() }),
    },

    -- User management — specific named paths before the parameterized /<uuid> route
    { name = "admin users list",            method = "GET",  path = [[^/admin/users$]],                  no_body = true },
    { name = "admin users overview",        method = "GET",  path = [[^/admin/users/overview$]],         no_body = true },
    { name = "admin users org-type",        method = "POST", path = [[^/admin/users/org_type$]],
      content_type = "application/json",
      json = T.object({
        -- Rust: NumberOrString (MembershipTypeData.user_type). Same
        -- MembershipType enum as "org user update"/"org users invite"
        -- (db/models/organization.rs: 0-3, plus legacy "Custom"=4) -- 0-4,
        -- not 0-255.
        user_type = T.number_or_string({ integer = true, min = 0, max = 4 }),
        user_uuid = T.uuid(),
        org_uuid  = T.uuid(),
      }),
    },
    { name = "admin users update-revision", method = "POST", path = [[^/admin/users/update_revision$]],  no_body = true },
    { name = "admin users by-mail",         method = "GET",
      path      = [[^/admin/users/by-mail/[^@\s/]+@[^@\s/]+\.[^@\s/]+$]],
      _test_uri = "/admin/users/by-mail/test@example.com",
      no_body   = true },

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
    -- No json schema for admin config post: the field set is open-ended and changes
    -- across Vaultwarden versions.  Content-type + max_body still enforced.
    { name = "admin config post",      method = "POST", path = [[^/admin/config$]],
      content_type = "application/json", max_body = 1024 * 1024,
    },
    { name = "admin config delete",    method = "POST", path = [[^/admin/config/delete$]],    no_body = true },
    { name = "admin config backup-db", method = "POST", path = [[^/admin/config/backup_db$]], no_body = true },

    -- Admin panel static assets (icons, CSS, JS bundled into the binary)
    -- (src/api/web.rs: GET /vw_static/<filename>)
    { name = "admin static", method = "GET", path = [[^/vw_static/[^/]+$]], no_body = true },

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
