local T = require "waf.types"

-- ---------------------------------------------------------------------------
-- Gitea WAF policy.
--
-- Phase 1 (REST API v1, /api/v1/*): see notes/apps/gitea/gitea-api-extract/
-- for the generation pipeline (full plan in TODO.txt, "GITEA WAF POLICY -
-- PHASE 1: REST API v1").
-- Phase 2 (web UI, below): see notes/apps/gitea/gitea-web-extract/ - a
-- brace/paren-depth-aware scanner over routers/web/web.go's
-- registerWebRoutes(), cross-referenced against services/forms/*.go for
-- bound-form field validation, same "spec/source is necessary but not
-- sufficient" cross-reference pattern as Phase 1.
-- Phase 3 (git smart-HTTP + LFS, below): small and fixed (~20 routes,
-- routers/web/githttp.go + services/lfs/*.go), hand-written rather than
-- generated - not worth a Python pipeline for a route count this size.
-- Not yet wired into any production nginx config - this policy still isn't
-- fully validated against real traffic (mode = "log" below).
-- ---------------------------------------------------------------------------

-- Authorization covers several of Gitea's auth shapes at once: "Bearer
-- <opaque personal access token>", "Bearer <OAuth2 JWT>", and
-- "Basic <base64 user:pass-or-token>" - unlike Vaultwarden's own
-- self-issued JWTs (a single strict format, see vw_auth_header in
-- vaultwarden.lua), Gitea's token formats genuinely vary, so this stays a
-- bounded generic check on the auth-scheme shape rather than trying to
-- validate token internals. Tighten later from real traffic if warranted.
local gitea_auth_header = T.string({ max = 2048, match = [[^(?:Bearer|Basic|token)\s+\S+$]] })

local api_schema = require "waf.apps.gitea.api_schema"
local web_routes = require "waf.apps.gitea.web_routes"

-- ---------------------------------------------------------------------------
-- Phase 3: git smart-HTTP + LFS.
--
-- Mounted at the bare repo root (/{owner}/{repo}/...), not under /api/v1 -
-- these are the endpoints real `git clone`/`push`/LFS clients hit, not
-- REST API consumers. `{reponame}` legitimately includes a literal ".git"
-- suffix on the wire (Gitea strips it internally via
-- strings.TrimSuffix(reponame, ".git"), confirmed directly in
-- services/lfs/locks.go - the router itself does no special-casing), which
-- the OWNER/REPO patterns below already allow since '.' is in their
-- continuation class.
-- ---------------------------------------------------------------------------

local OWNER = [[[\da-zA-Z][-.\w]{0,99}]]
local REPO  = [[[\da-zA-Z][-.\w]{0,99}]]
local LFS_OID = [[[0-9a-fA-F]{4,64}]]  -- real LFS OIDs are sha256 (64 hex), bounded generic below that

-- git-upload-pack/receive-pack/upload-archive carry the raw git wire
-- protocol as their body (binary pkt-line format) - no json/form schema
-- applies, just the exact Content-Type git itself requires (confirmed in
-- routers/web/repo/githttp.go's serviceRPC: `application/x-git-%s-request`)
-- and a much larger max_body than the API routes need (a full repo push
-- can be gigabytes; LFS object uploads even more so).
local GIT_PACK_MAX_BODY = 5 * 1024 * 1024 * 1024  -- 5 GiB

local git_lfs_routes = {
  -- git smart-HTTP (routers/web/githttp.go)
  { name = "gitea git upload-pack",   method = "POST",
    path = "^/" .. OWNER .. "/" .. REPO .. "/git-upload-pack$",
    content_types = { "application/x-git-upload-pack-request" }, max_body = GIT_PACK_MAX_BODY },
  { name = "gitea git receive-pack",  method = "POST",
    path = "^/" .. OWNER .. "/" .. REPO .. "/git-receive-pack$",
    content_types = { "application/x-git-receive-pack-request" }, max_body = GIT_PACK_MAX_BODY },
  { name = "gitea git upload-archive", method = "POST",
    path = "^/" .. OWNER .. "/" .. REPO .. "/git-upload-archive$",
    content_types = { "application/x-git-upload-archive-request" }, max_body = GIT_PACK_MAX_BODY },
  { name = "gitea git info refs", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. "/info/refs$",
    query = T.object({
      service = T.nullable(T.string({ max = 32, enum = { ["git-upload-pack"] = true, ["git-receive-pack"] = true } })),
    }) },
  { name = "gitea git HEAD file", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. "/HEAD$" },
  { name = "gitea git objects info alternates", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. "/objects/info/alternates$" },
  { name = "gitea git objects info http-alternates", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. "/objects/info/http-alternates$" },
  { name = "gitea git objects info packs", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. "/objects/info/packs$" },
  { name = "gitea git objects info file", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. [[/objects/info/[^/]*$]] },
  { name = "gitea git loose object", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. [[/objects/[0-9a-f]{2}/[0-9a-f]{38,62}$]] },
  { name = "gitea git pack file", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. [[/objects/pack/pack-[0-9a-f]{40,64}\.pack$]] },
  { name = "gitea git pack idx", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. [[/objects/pack/pack-[0-9a-f]{40,64}\.idx$]] },

  -- git-lfs (services/lfs/*.go, git-lfs's own well-documented batch API -
  -- https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md)
  { name = "gitea lfs batch", method = "POST",
    path = "^/" .. OWNER .. "/" .. REPO .. "/info/lfs/objects/batch$",
    content_types = { "application/vnd.git-lfs+json" },
    json = T.object({
      operation = T.string({ max = 16, enum = { upload = true, download = true } }),
      transfers = T.nullable(T.array(T.string({ max = 32 }), { max = 8 })),
      ref       = T.nullable(T.object({ name = T.string({ max = 512 }) })),
      objects   = T.array(T.object({
        oid  = T.string({ max = 64, match = [[^[0-9a-fA-F]+$]] }),
        size = T.number({ integer = true, min = 0, max = GIT_PACK_MAX_BODY }),
      }), { max = 1000 }),
    }, { required = { operation = true, objects = true } }) },
  { name = "gitea lfs object upload", method = "PUT",
    path = "^/" .. OWNER .. "/" .. REPO .. "/info/lfs/objects/" .. LFS_OID .. [[/[0-9]+$]],
    max_body = GIT_PACK_MAX_BODY },
  { name = "gitea lfs object download named", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. "/info/lfs/objects/" .. LFS_OID .. [[/[^/]{1,512}$]] },
  { name = "gitea lfs object download", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. "/info/lfs/objects/" .. LFS_OID .. "$" },
  { name = "gitea lfs verify", method = "POST",
    path = "^/" .. OWNER .. "/" .. REPO .. "/info/lfs/verify$",
    content_types = { "application/vnd.git-lfs+json" },
    json = T.object({
      oid  = T.string({ max = 64, match = [[^[0-9a-fA-F]+$]] }),
      size = T.number({ integer = true, min = 0, max = GIT_PACK_MAX_BODY }),
    }) },
  { name = "gitea lfs locks list", method = "GET", no_body = true,
    path = "^/" .. OWNER .. "/" .. REPO .. "/info/lfs/locks$",
    query = T.object({
      cursor = T.nullable(T.number_query({ integer = true, min = 0 })),
      limit  = T.nullable(T.number_query({ integer = true, min = 0 })),
      id     = T.nullable(T.number_query({ integer = true, min = 0 })),
      path   = T.nullable(T.string({ max = 1024 })),
    }) },
  { name = "gitea lfs locks create", method = "POST",
    path = "^/" .. OWNER .. "/" .. REPO .. "/info/lfs/locks$",
    content_types = { "application/vnd.git-lfs+json" },
    json = T.object({ path = T.string({ max = 1024 }) }, { required = { path = true } }) },
  -- Verify-locks reads cursor/limit via Gitea's ctx.FormInt (accepts either
  -- query string or form-encoded body depending on how the client sends
  -- it) rather than a strict JSON decode - modeled loosely (query params
  -- checked if present, body left unconstrained) rather than pinning down
  -- the exact mechanism and risking a false deny.
  { name = "gitea lfs locks verify", method = "POST",
    path = "^/" .. OWNER .. "/" .. REPO .. "/info/lfs/locks/verify$",
    query = T.object({
      cursor = T.nullable(T.number_query({ integer = true, min = 0 })),
      limit  = T.nullable(T.number_query({ integer = true, min = 0 })),
    }) },
  { name = "gitea lfs locks unlock", method = "POST",
    path = "^/" .. OWNER .. "/" .. REPO .. [[/info/lfs/locks/[0-9]+/unlock$]],
    content_types = { "application/vnd.git-lfs+json" },
    json = T.object({ force = T.nullable(T.boolean()) }) },
}

local all_routes = {}
for _, r in ipairs(api_schema.routes) do all_routes[#all_routes + 1] = r end
for _, r in ipairs(web_routes.routes) do all_routes[#all_routes + 1] = r end
for _, r in ipairs(git_lfs_routes)  do all_routes[#all_routes + 1] = r end

return {
  name = "gitea",
  mode = "log",   -- brand new and unvalidated - run in log mode against real traffic first

  defaults = {
    max_body        = 20 * 1024 * 1024,  -- issue/PR bodies and small file uploads via the API; per-route override for git/LFS (see GIT_PACK_MAX_BODY)
    allowed_methods = { GET = true, POST = true, PUT = true, DELETE = true, PATCH = true, OPTIONS = true },
    allowed_headers = T.common_request_headers(),
    headers = {
      ["authorization"] = gitea_auth_header,
    },
  },

  routes = all_routes,
}
