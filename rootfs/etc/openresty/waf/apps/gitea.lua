local T = require "waf.types"

-- ---------------------------------------------------------------------------
-- Gitea WAF policy - Phase 1: REST API v1 only (/api/v1/*).
--
-- See notes/apps/gitea/gitea-api-extract/ for the generation pipeline (the
-- full plan is saved in TODO.txt, "GITEA WAF POLICY - PHASE 1: REST API v1").
-- Web UI (routers/web/web.go routes + services/forms/*.go) and git
-- smart-HTTP/LFS are later phases - this policy alone does not cover the
-- routes real browser/git traffic hits, so it is not wired into any live
-- nginx config yet.
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

return {
  name = "gitea",
  mode = "log",   -- Phase 1, brand new and unvalidated - run in log mode against real traffic first

  defaults = {
    max_body        = 20 * 1024 * 1024,  -- issue/PR bodies and small file uploads via the API; tune from real traffic
    allowed_methods = { GET = true, POST = true, PUT = true, DELETE = true, PATCH = true, OPTIONS = true },
    allowed_headers = T.common_request_headers(),
    headers = {
      ["authorization"] = gitea_auth_header,
    },
  },

  routes = api_schema.routes,
}
