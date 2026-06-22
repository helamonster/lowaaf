# LOWAAF — Lua OpenResty Web Application and API Firewall

**A Positive Security Model, Whitelist Approach application firewall framework for [OpenResty](https://openresty.org), with declarative per-application policy definitions written in Lua.**

---

## What Is It?

LOWAAF is a lightweight, high-performance web application and API firewall framework that runs inside [OpenResty](https://openresty.org) (the Nginx/Lua platform). It sits in front of your web applications as a reverse proxy and enforces a strict, declarative security policy on every incoming HTTP request — validating the method, URI, headers, and request body before the request ever reaches your application.

Unlike traditional WAFs, LOWAAF is built on a **Positive Security Model**: every request is **denied by default**. A request is only permitted if it explicitly matches a declared route *and* passes all configured validation checks. There is no blacklist, no signature database, and no pattern matching against known exploits. Instead, you define exactly what your application is allowed to receive — and everything else is rejected.

---

## Why This Exists

This project grew out of a personal need. I self-host a number of services — a password manager, a media server, a wiki, and others — and I wanted a meaningful security layer in front of them that I could trust and understand completely. I didn't want to route my traffic through a third-party cloud WAF. I didn't want the complexity and false-positive noise of a generic rule set that knows nothing about my specific applications. And I didn't want to rely solely on hoping that the upstream application developers had caught every vulnerability before an attacker did.

What I wanted was a firewall that **knows exactly what my application's API looks like** and blocks anything that doesn't fit — not because it resembles a known attack pattern, but because it simply isn't a request my application should ever receive.

This framework is the result of formalizing that idea into a reusable, extensible system.

---

## The Problem with Blacklist-Based WAFs

Most popular WAFs — including [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity), [Coraza](https://coraza.io/), and threat intelligence platforms like [CrowdSec](https://www.crowdsec.net/) — operate on a **blacklist model**. They maintain a database of known attack signatures and block requests that match those patterns. The most widely deployed rule set for this approach is the [OWASP Core Rule Set (CRS)](https://owasp.org/www-project-modsecurity-core-rule-set/).

OWASP and the CRS are genuinely valuable. The OWASP Foundation does important work documenting common vulnerabilities and attack categories (the OWASP Top 10, for example, is an essential reference for any developer or administrator). The CRS provides broad, immediately deployable protection against a wide range of generic attacks — SQL injection, cross-site scripting, path traversal, and more — without requiring any knowledge of the specific application being protected.

**But blacklist-based protection has fundamental limitations:**

- **It only blocks what it already knows.** Zero-day exploits, novel attack techniques, and application-specific vulnerabilities are invisible to a signature database until someone writes a rule for them — after the fact.
- **It generates false positives.** Generic rules that don't understand your application's specific API will block legitimate traffic, requiring constant tuning and exceptions.
- **It assumes the application's attack surface is fixed and well-understood.** In practice, popular applications like WordPress, Drupal, Joomla, and countless plugins and themes have a long and ongoing history of critical vulnerabilities. New CVEs appear regularly. A blacklist WAF is always playing catch-up.
- **It provides no protection against application-specific logic flaws** — endpoints that accept unexpected parameters, fields that accept out-of-range values, or request shapes that the application mishandles.

The headline vulnerabilities affecting WordPress and its ecosystem are a clear illustration: despite mature WAF coverage, WordPress sites are compromised constantly — because each new plugin, each new version, each new integration introduces new attack surface that generic rules can't anticipate.

---

## The Positive Security Model

LOWAAF takes the opposite approach. Rather than asking *"does this request look malicious?"*, it asks *"is this request something my application should ever receive?"*

This is the **Whitelist Approach**: every route, every method, every header, every request body field is explicitly declared in a policy file. If a request doesn't match the declared policy, it is denied — regardless of whether it looks like an attack.

This approach aligns with **Zero Trust** principles: no request is trusted by default, and every request must prove it belongs before it is forwarded to the application. The framework doesn't trust the client, it doesn't trust that the request is well-formed, and it doesn't trust that the application will handle unexpected input safely.

The practical effect is significant:

- **Unknown attack vectors are blocked automatically.** If an attacker discovers a new vulnerability that requires sending an unexpected parameter, an unexpected header, or a request to an undeclared endpoint — LOWAAF blocks it, even with no knowledge of the vulnerability.
- **The policy is readable and auditable.** The security posture of an application is defined entirely in a single, human-readable Lua file. You can read it, review it, and understand exactly what the firewall permits.
- **False positives are near zero.** Because the policy is specific to the application, legitimate traffic is defined by the policy itself.
- **Protection is application-aware.** The policy can validate not just that a field is present, but its type, length, format, and allowed values — providing deep request inspection that generic WAFs cannot achieve.

---

## How It Works

LOWAAF runs as an `access_by_lua_block` handler inside an OpenResty `location` block. Before every request is proxied to the upstream application, the framework:

1. Checks the HTTP method against the application's globally allowed methods
2. Matches the request URI and method against the declared route table
3. Validates the client IP against any per-route allowlists (e.g., restricting admin endpoints to private networks)
4. Validates request headers — both the set of header names (allowlist) and their values (format validators)
5. Validates the request body — size limits, JSON schema, or form field schema

If any check fails, the request is denied. In `log` mode (the safe default), violations are logged but requests are passed through, allowing you to validate a policy against real traffic before enabling blocking. In `block` mode, violations result in a `4xx` response and the request never reaches the application.

```nginx
location /
{
    access_by_lua_block
    {
        local core = require "waf.core"
        local app  = require "waf.apps.vaultwarden"
        core.run(app)
    }
    proxy_pass http://127.0.0.1:8989;
}
```

---

## Framework Structure

```
waf/
  core.lua          # Engine — validates requests against an app policy
  types.lua         # Validator factory library — composable building blocks
  apps/
    vaultwarden.lua # Policy definition for Vaultwarden
    jellyfin.lua    # (in progress)
    mediawiki.lua   # (in progress)
```

### types.lua — Validator Factories

`types.lua` provides composable validator factories. Each factory returns a `function(value, path) -> true | false, err` that can be used anywhere in a policy definition.

```lua
local T = require "waf.types"

-- primitives
T.string({ min=1, max=256, match=[[^[a-z]+$]] })
T.number({ integer=true, min=0, max=100 })
T.boolean()
T.uuid()
T.email()

-- composites
T.nullable(T.uuid())
T.array(T.uuid(), { max=200 })
T.object({ name = T.string({ max=256 }), active = T.boolean() })

-- HTTP helpers
T.common_request_headers()   -- standard browser header name list
T.common_proxy_headers()     -- reverse-proxy header name list
T.merge_headers(...)         -- flatten multiple lists
T.content_type_json()        -- Content-Type value validators
T.bearer_token()             -- Authorization: Bearer format
```

### App Policy Files — Declarative and Readable

Each application firewall is a single Lua file that returns a policy table. It contains no parsing logic — only declarations. The framework handles all parsing, validation, and enforcement.

```lua
local T = require "waf.types"

return {
  name = "myapp",
  mode = "log",   -- switch to "block" after validating against real traffic

  defaults = {
    max_body        = 1024 * 1024,
    allowed_methods = { GET=true, POST=true, PUT=true, DELETE=true },
    allowed_headers = T.common_request_headers(),
    headers = {
      ["User-Agent"] = T.string({ max=512, match=[[Mozilla/5\.0]] }),
    },
  },

  routes = {
    {
      name         = "login",
      method       = "POST",
      path         = [[^/api/login$]],
      content_type = "application/json",
      json = T.object({
        username = T.email(),
        password = T.string({ min=8, max=1024 }),
      }),
    },
    {
      name    = "dashboard",
      method  = "GET",
      path    = [[^/dashboard$]],
      no_body = true,
    },
  }
}
```

---

## Current Application Policies

| Application | Status | Notes |
|---|---|---|
| [Vaultwarden](https://github.com/dani-garcia/vaultwarden) | Working (log mode) | Full route coverage, cipher/login/send schemas, UA restriction |
| Jellyfin | Partial PoC | Pre-framework implementation, migration in progress |
| MediaWiki | Partial PoC | Pre-framework implementation, migration in progress |

---

## Roadmap

This project is actively being developed and improved. Planned work includes:

- **More application policies** — Jellyfin, MediaWiki, WordPress, and others migrated to the new framework
- **Stricter schemas** — deeper JSON validation on more endpoints as real-traffic log analysis reveals the actual request shapes clients send
- **Rate limiting integration** — per-route and per-client request rate limits
- **IPv6 CIDR support** — IP allowlists currently handle IPv4 only
- **Query string validation** — allowlisting and validating URI query parameters
- **Response filtering** — optionally inspect and sanitize upstream responses
- **More templates** — additional `T.*` helpers for common patterns (JWT validation, API key formats, common header value shapes)
- **Testing infrastructure** — unit tests for the framework engine and validator library

---

## Policy Files as API Documentation

A LOWAAF policy file does something valuable beyond security enforcement: it serves as the **authoritative, executable specification of an application's API**.

Every route your application exposes, every HTTP method it accepts, every header it expects, every field it reads from a request body — all of it is declared explicitly, in one place, in human-readable form. When the policy is running in `block` mode, that declaration isn't just documentation — it is the enforced contract between the outside world and your application.

This has significant implications for both existing and new applications:

- **Existing applications** often have undocumented, untested, or forgotten endpoints. Writing a LOWAAF policy forces a complete audit of the actual API surface. Any endpoint that can't be declared precisely is an endpoint that isn't understood — and that's exactly where vulnerabilities hide.
- **New applications** should have a LOWAAF policy written alongside the API itself, as a first-class artifact of development. The policy defines what the API is *supposed* to accept, with no ambiguity. It prevents scope creep and accidental exposure of unintended functionality.
- **Third-party and open-source applications** benefit from community-maintained policies in this repository: when the upstream application ships an update, the policy can be reviewed against the changelog to determine whether new routes or parameters need to be declared — a structural prompt to audit every change.

The practice of writing a policy for every web application you deploy — whether you built it yourself or installed it from upstream — is strongly recommended. It removes ambiguity, creates a verifiable record of intent, and provides a security guarantee that no amount of code review alone can match: the application *cannot* receive a request that wasn't explicitly anticipated.

---

## Why Open Source?

The security of self-hosted applications shouldn't require a commercial product or a cloud dependency. A positive-security WAF is most useful when it is:

- **Auditable** — you can read every line and understand exactly what it permits and denies
- **Adaptable** — you can write a policy for any application, not just ones a vendor has chosen to support
- **Community-maintained** — application APIs change, and a shared repository of up-to-date policies benefits everyone running the same software

If you self-host any of the applications covered by this project, you benefit directly from the policies here. And if you contribute improvements — tighter schemas, new application policies, bug fixes — everyone benefits.

---

## Requirements

- [OpenResty](https://openresty.org) (any recent version with LuaJIT)
- The `lua_package_path` directive configured to include the `waf/` directory:

```nginx
# in the http {} block of nginx.conf
lua_package_path "/path/to/waf/?.lua;;";
```

---

## Author

**Jeremy Bryan Smith** — [jeremybryansmith.com](https://jeremybryansmith.com) — helamonster@gmail.com

Developed with assistance from [Claude](https://claude.ai) (Anthropic).
