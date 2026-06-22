local T = require "waf.types"

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
  uri   = nu_enc,
  match = T.nullable(T.number({ integer = true, min = 0, max = 5 })),
})

local cipher_field = T.object({
  type     = T.nullable(T.number({ integer = true, min = 0, max = 3 })),
  name     = nu_enc,
  value    = nu_enc,
  linkedId = nu_num,
})

local cipher_body = T.object({
  type            = T.number({ integer = true, min = 1, max = 4 }),
  name            = enc,
  notes           = nu_enc,
  favorite        = nu_bool,
  folderId        = nu_uuid,
  organizationId  = nu_uuid,
  collectionIds   = T.nullable(T.array(T.uuid(), { max = 200 })),
  reprompt        = T.nullable(T.number({ integer = true, min = 0, max = 1 })),
  fields          = T.nullable(T.array(cipher_field, { max = 100 })),
  passwordHistory = T.nullable(T.array(T.object({
    lastUsedDate = T.string({ max = 64 }),
    password     = enc,
  }), { max = 200 })),
  login = T.nullable(T.object({
    username = nu_enc,
    password = nu_enc,
    totp     = nu_enc,
    uris     = T.nullable(T.array(cipher_uri, { max = 100 })),
  })),
  card = T.nullable(T.object({
    cardholderName = nu_enc,
    brand          = nu_enc,
    number         = nu_enc,
    expMonth       = nu_enc,
    expYear        = nu_enc,
    code           = nu_enc,
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
  })),
  secureNote = T.nullable(T.object({
    type = T.number({ integer = true, min = 0, max = 0 }),
  })),
})

-- ---------------------------------------------------------------------------
return {
  name = "vaultwarden",
  mode = "log",   -- flip to "block" after validating against real traffic

  defaults = {
    max_body = 5 * 1024 * 1024,  -- 5 MB; covers attachment uploads
    allowed_methods = {
      GET = true, POST = true, PUT = true, DELETE = true, OPTIONS = true,
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
        deviceType        = T.nullable(T.number({ integer = true, min = 0, max = 30 })),
        deviceIdentifier  = nu_sml,
        deviceName        = nu_sml,
        devicePushToken   = nu_sml,
        twoFactorToken    = nu_sml,
        twoFactorProvider = T.nullable(T.number({ integer = true, min = 0, max = 10 })),
        twoFactorRemember = T.nullable(T.number({ integer = true, min = 0, max = 1 })),
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
    { name = "ciphers archive",    method = "PUT",    path = [[^/api/ciphers/archive$]] },
    { name = "ciphers unarchive",  method = "PUT",    path = [[^/api/ciphers/unarchive$]] },
    { name = "ciphers import",     method = "POST",   path = [[^/api/ciphers/import$]],              content_type = "application/json" },
    { name = "ciphers bulk-delete",method = "DELETE", path = [[^/api/ciphers$]] },

    -- ATTACHMENTS -----------------------------------------------------------

    { name = "attachment create-v2", method = "POST",   path = "^/api/ciphers/" .. U .. "/attachment/v2$" },
    { name = "attachment get",       method = "GET",    path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "$", no_body = true },
    { name = "attachment upload",    method = "POST",   path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "$" },
    { name = "attachment delete",    method = "DELETE", path = "^/api/ciphers/" .. U .. "/attachment/" .. FILEID .. "$", no_body = true },

    -- FOLDERS ---------------------------------------------------------------

    { name = "folder list",   method = "GET",    path = [[^/api/folders$]],           no_body = true },
    { name = "folder create", method = "POST",   path = [[^/api/folders$]],           content_type = "application/json" },
    { name = "folder get",    method = "GET",    path = "^/api/folders/" .. U .. "$", no_body = true },
    { name = "folder update", method = "PUT",    path = "^/api/folders/" .. U .. "$", content_type = "application/json" },
    { name = "folder delete", method = "DELETE", path = "^/api/folders/" .. U .. "$", no_body = true },

    -- SENDS -----------------------------------------------------------------

    { name = "send list",        method = "GET",    path = [[^/api/sends$]],                                              no_body = true },
    { name = "send create",      method = "POST",   path = [[^/api/sends$]],                                              content_type = "application/json" },
    { name = "send create-file", method = "POST",   path = [[^/api/sends/file/v2$]] },
    { name = "send get",         method = "GET",    path = "^/api/sends/" .. U .. "$",                                    no_body = true },
    { name = "send update",      method = "PUT",    path = "^/api/sends/" .. U .. "$",                                    content_type = "application/json" },
    { name = "send delete",      method = "DELETE", path = "^/api/sends/" .. U .. "$",                                    no_body = true },
    { name = "send file upload", method = "POST",   path = "^/api/sends/" .. U .. "/file/" .. FILEID .. "$" },
    { name = "send access",      method = "POST",   path = [[^/api/sends/[^/]+/access$]] },

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
    { name = "verify email",       method = "POST",   path = [[^/api/accounts/verify-email$]] },
    { name = "verify email token", method = "POST",   path = [[^/api/accounts/verify-email-token$]], content_type = "application/json" },
    { name = "delete account",     method = "DELETE", path = [[^/api/accounts$]] },

    -- TWO FACTOR ------------------------------------------------------------

    { name = "2fa list",          method = "GET",  path = [[^/api/two-factor$]],                   no_body = true },
    { name = "2fa get-recover",   method = "POST", path = [[^/api/two-factor/get-recover$]],       content_type = "application/json" },
    { name = "2fa recover",       method = "POST", path = [[^/api/two-factor/recover$]],           content_type = "application/json" },
    { name = "2fa get-webauthn",  method = "POST", path = [[^/api/two-factor/get-webauthn$]],      content_type = "application/json" },
    { name = "2fa get-duo",       method = "POST", path = [[^/api/two-factor/get-duo$]],           content_type = "application/json" },
    { name = "2fa get-totp",      method = "POST", path = [[^/api/two-factor/get-authenticator$]], content_type = "application/json" },
    { name = "2fa get-yubikey",   method = "POST", path = [[^/api/two-factor/get-yubikey$]],       content_type = "application/json" },
    { name = "2fa get-email",     method = "POST", path = [[^/api/two-factor/get-email$]],         content_type = "application/json" },
    { name = "2fa send-email",    method = "POST", path = [[^/api/two-factor/send-email-login$]] },

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

    { name = "notifications hub", method = "GET", path = [[^/notifications/hub$]] },

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
