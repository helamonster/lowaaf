# openresty-waaapi-firewall

A **positive-security Web Application and API Firewall (WAAAPI)** framework for OpenResty, plus per-application policy definitions built on top of it.

The security model is **deny-by-default**: every request must match a declared route and pass schema validation, or it is blocked. This is deliberately stricter than signature-based WAFs (ModSecurity/OWASP CRS) — it whitelists the known-good API surface rather than blacklisting known-bad patterns.


## Project layout (target state)

```
rootfs/etc/openresty/waf/
  core.lua          # app-agnostic engine: routing, parsing, validation dispatch, deny/log
  types.lua         # reusable type-validator factories
  apps/
    vaultwarden.lua # declarative route+schema policy for Vaultwarden
    jellyfin.lua    # declarative route+schema policy for Jellyfin
    mediawiki.lua   # declarative route+schema policy for MediaWiki
```

The nginx config for each application loads the framework with two lines:

```nginx
access_by_lua_block {
    local core = require "waf.core"
    local app  = require "waf.apps.vaultwarden"
    core.run(app)
}
```


## Framework modules

### types.lua — validator factories

Returns a table `T` of factory functions. Each factory returns a `function(value, path) -> ok, err` validator:

| Factory | Key options |
|---|---|
| `T.string(opts)` | `min`, `max`, `match` (regex), `not_match`, `enum` |
| `T.number(opts)` | `min`, `max`, `integer` |
| `T.boolean()` | — |
| `T.uuid()` | wraps `T.string` with UUID regex |
| `T.email()` | wraps `T.string` with email constraints |
| `T.nullable(inner)` | passes if value is nil/null, else delegates to `inner` |
| `T.array(inner, opts)` | `max` (array length); validates each element with `inner` |
| `T.object(schema, opts)` | rejects unknown keys; validates known keys; `opts.required` |

### core.lua — engine

`core.run(app)` executes in order:
1. Global method check against `app.defaults.allowed_methods`
2. Route match (first `methods`+`paths` pair that matches wins)
3. IP allowlist check (`route.allow_ips`)
4. Content-type check (`route.content_types`)
5. Body-size check (`route.max_body` or `app.defaults.max_body`)
6. No-body enforcement (`route.no_body = true`)
7. JSON schema validation (`route.json_schemas`) — tries each schema, passes if any matches
8. Form schema validation (`route.form_schemas`) — same
9. If no route matched → deny 404

In `mode = "log"` the engine logs what would be denied but does not block. Flip to `mode = "block"` once real traffic validates the policy.

### apps/<name>.lua — app policy

App files contain **only** declarative data — no parsing logic. Shape:

```lua
local T = require "waf.types"

return {
  name = "appname",
  mode = "log",   -- "log" | "block"

  defaults = {
    max_body         = 1024 * 1024,
    allowed_methods  = { GET=true, POST=true, PUT=true, DELETE=true, OPTIONS=true },
  },

  routes = {
    {
      name          = "human-readable label",
      methods       = { "POST" },             -- or singular: method = "POST"
      paths         = { [[^/some/path$]] },   -- or singular: path = ...
      content_types = { "application/json" }, -- optional
      no_body       = false,                  -- true to reject any body
      allow_ips     = { "10.0.0.0/8" },       -- optional IP allowlist
      max_body      = 65536,                  -- optional override
      json_schemas  = { T.object({...}) },    -- or singular: json = ...
      form_schemas  = { T.object({...}) },    -- or singular: form = ...
    },
  }
}
```

Route fields all support **singular or plural aliases** (`method`/`methods`, `path`/`paths`, etc.). The engine normalizes them internally.


## Implementation phases (per app)

1. URI + method whitelist (deny everything not in the route table)
2. Admin endpoint IP lockdown
3. Content-type and body-size enforcement
4. Query/form key whitelist
5. JSON top-level key whitelist
6. Nested JSON schema validation
7. Value-level restrictions (enums, length limits, regex formats)
8. Run in `mode = "log"` against real traffic, then flip to `mode = "block"`


## Existing proof-of-concept

`rootfs/` contains a working but pre-framework PoC for Jellyfin and MediaWiki. It uses a flat policy table with `validator` callbacks rather than the declarative DSL described above. It also includes IP-banning via a FIFO pipe to ipset on denied requests — a useful feature to carry into the framework as an optional deny hook.

The PoC is useful as a reference for what endpoints each app actually uses, but the architecture should converge toward the framework layout above.


## Deployment context

- Home lab, self-hosted services behind OpenResty
- Services are WireGuard-accessible; some are also internet-facing
- OpenResty's `lua_package_path` should include `/etc/openresty/?.lua`
- No Cloudflare or third-party WAF in the stack
