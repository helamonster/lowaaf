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
-- mediawiki.lua : LOWAAF policy for MediaWiki
--
-- MediaWiki: The free and open-source wiki software
-- <https://www.mediawiki.org>
--
-- --------------------------------------------------------------------------------------

local T = require "waf.types"

-- ---------------------------------------------------------------------------
-- MediaWiki-specific headers
-- MediaWiki clients send a few headers beyond the common browser set:
--   api-user-agent  - identifies API consumers (bots, scripts)
--   x-requested-with - sent by jQuery AJAX calls
--   sec-gpc         - Global Privacy Control
--   priority        - HTTP/2 request priority
--   amp-cache-transform - AMP CDN header (some environments)
--   from            - RFC 2822 sender (some bots)
-- ---------------------------------------------------------------------------
local _mw_extra_headers = {
  "api-user-agent",
  "x-requested-with",
  "amp-cache-transform",
  "from",
}

-- ---------------------------------------------------------------------------
-- index.php query parameter schema
--
-- MediaWiki routes nearly all page requests through index.php. Rather than
-- one big union of every known-good param (permissive: any param is valid on
-- any page), params are split into:
--   idx_common       - valid on every /index.php request regardless of page
--   mw_special_pages - per-Special-page extra params, precisely gated so they
--                      are only accepted when the request is actually for
--                      that page (via title=<page> or the matching clean-path
--                      route below), not merely present anywhere.
-- A Special: page reached by clean path (/index.php/Special:Foo) gets its
-- own dedicated route further down with an unconditional extra-params
-- schema; the ?title=Special:Foo query-string form is validated here via
-- index_query_check, since routing only sees the URI path, never the query
-- string.
-- ---------------------------------------------------------------------------

-- Shallow-merges one or more {key=validator} tables into a new table; later
-- tables' keys win on conflict.
local function merge(...)
  local out = {}
  for _, t in ipairs({...}) do
    for k, v in pairs(t) do out[k] = v end
  end
  return out
end

local idx_common = {
  -- navigation / page identity
  title           = T.string({ max=512 }),
  curid           = T.string({ max=20 }),  -- alternative to title=; ActionEntryPoint::performAction() resolves either
  action          = T.string({ max=64 }),
  redlink         = T.string({ max=8 }),
  returnto        = T.string({ max=512 }),
  returntoquery   = T.string({ max=512 }),
  redirect        = T.string({ max=8 }),
  useskin         = T.string({ max=64 }),
  wprov           = T.string({ max=64 }),
  uselang         = T.string({ max=16 }),  -- also used by load.php

  -- search
  search          = T.string({ max=512 }),
  go              = T.string({ max=64 }),
  profile         = T.string({ max=64 }),
  fulltext        = T.string({ max=8 }),

  -- namespace toggles (ns0..ns15)
  ns0  = T.string({ max=4 }), ns1  = T.string({ max=4 }),
  ns2  = T.string({ max=4 }), ns3  = T.string({ max=4 }),
  ns4  = T.string({ max=4 }), ns5  = T.string({ max=4 }),
  ns6  = T.string({ max=4 }), ns7  = T.string({ max=4 }),
  ns8  = T.string({ max=4 }), ns9  = T.string({ max=4 }),
  ns10 = T.string({ max=4 }), ns11 = T.string({ max=4 }),
  ns12 = T.string({ max=4 }), ns13 = T.string({ max=4 }),
  ns14 = T.string({ max=4 }), ns15 = T.string({ max=4 }),
  namespace       = T.string({ max=16 }),

  -- pagination / filtering
  limit           = T.string({ max=10 }),
  offset          = T.string({ max=20 }),
  from            = T.string({ max=32 }),
  fromFormatted   = T.string({ max=32 }),
  dir             = T.string({ max=16 }),
  days            = T.string({ max=6 }),
  hidebots        = T.string({ max=4 }),
  enhanced        = T.string({ max=4 }),
  -- Shared ChangesListSpecialPage filter system (RecentChanges/Watchlist/
  -- RecentChangesLinked all use it) - registered via getBaseFilterGroupDefinitions()
  -- / getExtraFilterGroupDefinitions() (includes/SpecialPage/ChangesListSpecialPage.php,
  -- includes/Specials/SpecialRecentChanges.php, includes/Specials/SpecialWatchlist.php),
  -- not $request->getVal() calls the heuristic scanner can see - confirmed live:
  -- ?userExpLevel=unregistered on Special:RecentChanges got denied. hidebots above is
  -- from this exact same system, already treated as universal; these are its siblings.
  userExpLevel    = T.string({ max=128 }),  -- pipe-separated: unregistered|registered|newcomer|learner|experienced
  reviewStatus    = T.string({ max=32 }),   -- pipe-separated: unpatrolled|manual|auto
  watchlist       = T.string({ max=32 }),   -- pipe-separated: watched|watchednew|notwatched (RecentChanges-specific)
  watchlistactivity = T.string({ max=16 }), -- pipe-separated: unseen|seen (Watchlist-specific)
  hidebyothers    = T.string({ max=4 }),
  hidehumans      = T.string({ max=4 }),
  hidemajor       = T.string({ max=4 }),
  hidelastrevision = T.string({ max=4 }),
  hidepreviousrevisions = T.string({ max=4 }),
  hidepageedits   = T.string({ max=4 }),
  hidenewpages    = T.string({ max=4 }),
  hidelog         = T.string({ max=4 }),
  hidenewuserlog  = T.string({ max=4 }),
  hideunpatrolled = T.string({ max=4 }),
  extended        = T.string({ max=4 }),    -- Watchlist-specific
  urlversion      = T.string({ max=4 }),
  peek            = T.string({ max=4 }),
  isAnon          = T.string({ max=8 }),

  -- diff / history
  diff            = T.string({ max=20 }),
  oldid           = T.string({ max=20 }),
  direction       = T.string({ max=16 }),
  undoafter       = T.string({ max=20 }),
  undo            = T.string({ max=20 }),

  -- edit / submit
  section         = T.string({ max=16 }),

  -- feed
  feed            = T.string({ max=16 }),

  -- log / special pages
  page            = T.string({ max=512 }),
  user            = T.string({ max=256 }),
  username        = T.string({ max=256 }),
  tagfilter       = T.string({ max=256 }),
  wpdate          = T.string({ max=32 }),
  type            = T.string({ max=64 }),
  group           = T.string({ max=64 }),
  force           = T.string({ max=8 }),
  editsOnly       = T.string({ max=8 }),
  temporaryGroupsOnly = T.string({ max=8 }),
  wpsubmit        = T.string({ max=64 }),
  wpFormIdentifier= T.string({ max=64 }),
  wpTarget        = T.string({ max=512 }),
  blockType       = T.string({ max=32 }),
  prefix          = T.string({ max=256 }),
  lang            = T.string({ max=16 }),
  error           = T.string({ max=64 }),
  warning         = T.string({ max=64 }),
  isbn            = T.string({ max=32 }),
  filename        = T.string({ max=512 }),
  target          = T.string({ max=512 }),  -- bare "/index.php?target=" front-page usage

  -- array-style params (MediaWiki passes these as key[])
  ["wpOptions[]"] = T.string({ max=64 }),

  -- filter: enum-constrained everywhere (only known-good on Special:AllMessages,
  -- but the value set is small enough to be safe globally)
  filter          = T.string({ max=16, enum={ unmodified=true, all=true, modified=true } }),
}

-- Per-Special-page extra params. Each entry's fields are only accepted when
-- the request's `title` matches one of the page names that use them (see
-- index_query_check below) — this is what makes the whitelisting precise
-- rather than a flat union.
local mw_special_pages = {
  { label = "allpages", titles = { "Special:AllPages" },
    fields = { to = T.string({ max=512 }), hideredirects = T.string({ max=4 }) } },
  { label = "listusers", titles = { "Special:ListUsers" },
    fields = { creationSort = T.string({ max=8 }), desc = T.string({ max=8 }) } },
  { label = "recentchangeslinked", titles = { "Special:RecentChangesLinked" },
    fields = { showlinkedto = T.string({ max=4 }) } },
  { label = "redirect", titles = { "Special:Redirect" },
    fields = { wptype = T.string({ max=32 }), wpvalue = T.string({ max=512 }) } },
  { label = "protectedtitles", titles = { "Special:ProtectedTitles" },
    fields = { level = T.string({ max=8 }) } },
  { label = "log", titles = { "Special:Log" },
    fields = {
      ["wpfilters[]"] = T.string({ max=64 }),
      subtype         = T.string({ max=64 }),
      logid           = T.string({ max=20 }),
      pattern         = T.string({ max=256 }),
      tagInvert       = T.string({ max=4 }),
    } },
  { label = "activeusers", titles = { "Special:ActiveUsers" },
    fields = {
      ["groups[]"]        = T.string({ max=64 }),
      ["excludegroups[]"] = T.string({ max=64 }),
    } },
  { label = "comparepages", titles = { "Special:ComparePages" },
    fields = {
      rev1   = T.string({ max=20 }), rev2  = T.string({ max=20 }),
      unhide = T.string({ max=4 }),
      page1  = T.string({ max=512 }), page2 = T.string({ max=512 }),
    } },
  { label = "shared_target", titles = { "Special:WhatLinksHere", "Special:RecentChangesLinked", "Special:LinkSearch", "Special:MergeHistory" },
    fields = { target = T.string({ max=512 }) } },  -- shared across several pages
  { label = "whatlinkshere", titles = { "Special:WhatLinksHere" },
    fields = {
      invert     = T.string({ max=4 }),
      hidetrans  = T.string({ max=4 }),
      hidelinks  = T.string({ max=4 }),
      hideredirs = T.string({ max=4 }),
    } },
  { label = "mimesearch", titles = { "Special:MIMESearch" },
    fields = { mime = T.string({ max=64 }) } },
  { label = "newpages", titles = { "Special:NewPages" },
    fields = {
      ["size-mode"] = T.string({ max=8 }),
      size          = T.number_query({ integer=true, min=0, max=17592186044416 }),
      associated    = T.string({ max=4 }),
      invert        = T.string({ max=4 }),
      hideliu       = T.string({ max=4 }),
      hideredirs    = T.string({ max=4 }),
      hidepatrolled = T.string({ max=4 }),
    } },
  { label = "mergehistory", titles = { "Special:MergeHistory" },
    fields = {
      dest       = T.string({ max=512 }),
      submitted  = T.string({ max=4 }),
      mergepoint = T.string({ max=32 }),
    } },
  { label = "pageswithprop", titles = { "Special:PagesWithProp" },
    fields = {
      propname    = T.string({ max=64 }),
      reverse     = T.string({ max=4 }),
      sortbyvalue = T.string({ max=4 }),
    } },
  { label = "contributions", titles = { "Special:Contributions" },
    fields = {
      start           = T.string({ max=32 }),
      ["end"]         = T.string({ max=32 }),
      ["wpfilters[]"] = T.string({ max=64 }),
      tagInvert       = T.string({ max=4 }),
      topOnly         = T.string({ max=4 }),
      newOnly         = T.string({ max=4 }),
      hideMinor       = T.string({ max=4 }),
    } },
}

-- Same {label, titles, fields} shape as mw_special_pages above, but covering
-- the remaining ~116 Special: pages (everything NOT hand-tuned above) -
-- reassigned (not re-`local`'d) further down in this file, from the
-- generated Tier 6 block (gen_all_special_pages.py's get_extra_fields,
-- shared with each page's own dedicated GET route). Forward-declared here,
-- before index_query_check/mw_special_fields below need it, since
-- index_query_check's closure captures it as an upvalue by reference - it
-- only actually gets read at request-validation time, long after the whole
-- module (including the later reassignment) has finished loading. Without
-- this, a Special: page reached via ?title=Special:X query-string style
-- (not /index.php/Special:X path style) only ever saw idx_common's bare
-- baseline, never its own page-specific fields - confirmed live for
-- Special:PrefixIndex's prefix/namespace/hideredirects/stripprefix.
local mw_bulk_special_query_pages = {}

local mw_pages_by_label = {}
for _, page in ipairs(mw_special_pages) do
  mw_pages_by_label[page.label] = page
end

-- Merged field set for one or more page labels, e.g. page_fields("whatlinkshere", "shared_target").
local function page_fields(...)
  local tables = {}
  for _, label in ipairs({...}) do
    tables[#tables+1] = mw_pages_by_label[label].fields
  end
  return merge(unpack(tables))
end

-- Cross-field check: any key declared in mw_special_pages is only allowed
-- when `title` matches one of the page names that declare it. Also tightens
-- `limit` to an integer 0-100 specifically on Special:AllMessages.
-- MediaWiki case-folds special page names before resolving them
-- (SpecialPageFactory::resolveAlias()), so ?title=Special:allpages and
-- ?title=Special:AllPages both work in real MediaWiki - title comparisons
-- below match case-insensitively for the same reason the route path
-- patterns use the (?i) PCRE modifier.
local function title_is(title, page_name)
  if type(title) ~= "string" then return false end
  -- MediaWiki's Special: page "subpage" syntax embeds the target as a path
  -- suffix (e.g. title=Special:WhatLinksHere/Some_Page), not just a bare
  -- exact page name - match that prefix form too, not only exact equality.
  local t, p = title:lower(), page_name:lower()
  return t == p or t:sub(1, #p + 1) == p .. "/"
end

-- Iterates mw_special_pages (hand-tuned, 16 pages) then
-- mw_bulk_special_query_pages (generated, the remaining ~116) as if they
-- were one table - two separate tables instead of one combined local so the
-- generated block can be wholesale-replaced each regen without disturbing
-- the hand-tuned entries above it.
local function each_special_query_page(fn)
  for _, page in ipairs(mw_special_pages) do fn(page) end
  for _, page in ipairs(mw_bulk_special_query_pages) do fn(page) end
end

local function index_query_check(v, path)
  for key in pairs(v) do
    -- idx_common fields are unconditionally valid on every /index.php
    -- request; never gate one just because some page's heuristic field scan
    -- happened to also pick up a $request->getVal() call using the same
    -- name (confirmed live: SpecialApiHelp.php reads 'title', which - being
    -- one of idx_common's own keys - briefly made `title` itself only
    -- "valid for its specific Special: page" for every request, everywhere).
    if idx_common[key] == nil then
      local is_gated, matched = false, false
      each_special_query_page(function(page)
        if page.fields[key] ~= nil then
          is_gated = true
          for _, t in ipairs(page.titles) do
            if title_is(v.title, t) then matched = true end
          end
        end
      end)
      if is_gated and not matched then
        return false, path .. "." .. key .. ": only valid for its specific Special: page"
      end
    end
  end

  if title_is(v.title, "Special:AllMessages") and v.limit ~= nil then
    local n = tonumber(v.limit)
    if not n or n ~= math.floor(n) or n < 0 or n > 100 then
      return false, path .. ".limit: must be an integer 0-100 on Special:AllMessages"
    end
  end

  return true
end

-- mw_special_fields/index_query themselves are built much further down (see
-- the comment there) - not here, even though everything else Special:-page
-- related lives in this section - because they depend on
-- mw_bulk_special_query_pages, which isn't reassigned to its real content
-- until the generated Tier 6 block runs, later in this file.

-- One dedicated route per Special: page reached via clean path
-- (/index.php/Special:Foo), so the extra fields are unconditionally valid
-- without needing title= gating (routing already proves which page it is).
local function special_page_route(label, page_name, fields)
  -- (?i): MediaWiki case-folds special page names before resolving them
  -- (SpecialPageFactory::resolveAlias()), so /index.php/Special:allpages
  -- and /index.php/Special:AllPages both work in real MediaWiki - the WAF
  -- needs to accept either rather than betting on one exact casing.
  return {
    name    = "index php special " .. label,
    method  = "GET",
    path    = [[(?i)^/index\.php/]] .. page_name .. [[(?:/.*)?$]],  -- page_name is a fixed literal, no regex metachars to escape
    query   = T.object(merge(idx_common, fields)),
    no_body = true,
  }
end

-- Special:AllMessages doesn't add any new keys (filter/limit are already in
-- idx_common) — it just tightens `limit` to an integer 0-100. index_query
-- already does this for the ?title=Special:AllMessages form; this route
-- covers the clean-path form, where `title` is never set so that check
-- never fires.
local function allmessages_limit_check(v, path)
  if v.limit ~= nil then
    local n = tonumber(v.limit)
    if not n or n ~= math.floor(n) or n < 0 or n > 100 then
      return false, path .. ".limit: must be an integer 0-100 on Special:AllMessages"
    end
  end
  return true
end

local allmessages_route = {
  name    = "index php special allmessages",
  method  = "GET",
  path    = [[(?i)^/index\.php/Special:AllMessages(?:/.*)?$]],
  query   = T.with_check(T.object(idx_common), allmessages_limit_check),
  no_body = true,
}

-- ---------------------------------------------------------------------------
-- api.php multiplexes ~50 distinct "modules" through one endpoint via the
-- `action` parameter (which itself further fans out via action=query's own
-- prop=/list=/meta= submodules). Each module's PHP class declares its exact
-- parameter set via getAllowedParams() - see includes/Api/Api*.php in the
-- MediaWiki source, mechanically extracted by extract-mediawiki-api.sh into
-- mw-api-extract/api-params.json. mw_api_actions below is populated action by
-- action from that extraction as each one gets precisely modeled; an action
-- not yet present here falls back to api_legacy_fields (the older, generic
-- field set) so coverage only gets stricter over time, one tier at a time,
-- rather than suddenly rejecting real traffic for actions not yet migrated.
-- ---------------------------------------------------------------------------

-- True common params, valid on every api.php request regardless of action
-- (ApiMain::getAllowedParams() itself, not any specific action module).
local api_common = {
  action           = T.nullable(T.string({ max=64 })),
  format           = T.nullable(T.string({ max=16 })),
  formatversion    = T.nullable(T.string({ max=4 })),
  maxlag           = T.nullable(T.number_query({ integer=true })),
  smaxage          = T.nullable(T.number_query({ integer=true, min=0 })),
  maxage           = T.nullable(T.number_query({ integer=true, min=0 })),
  ["assert"]       = T.nullable(T.string({ max=8, enum={ anon=true, user=true, bot=true } })),
  assertuser       = T.nullable(T.string({ max=256 })),
  requestid        = T.nullable(T.string({ max=256 })),
  servedby         = T.nullable(T.string({ max=8 })),
  curtimestamp     = T.nullable(T.string({ max=8 })),
  responselanginfo = T.nullable(T.string({ max=8 })),
  origin           = T.nullable(T.string({ max=512 })),
  crossorigin      = T.nullable(T.string({ max=8 })),
  uselang          = T.nullable(T.string({ max=16 })),
  variant          = T.nullable(T.string({ max=16 })),
  errorformat      = T.nullable(T.string({ max=16, enum={
    plaintext=true, wikitext=true, html=true, raw=true, none=true, bc=true,
  } })),
  errorlang        = T.nullable(T.string({ max=16 })),
  errorsuselocal   = T.nullable(T.string({ max=8 })),
  callback         = T.nullable(T.string({ max=256 })),  -- format=json callback name
}

-- Generic fields kept allowed (but not precisely typed) for actions not yet
-- migrated into mw_api_actions below - remove an entry here once its action
-- gets a precise entry, so it's covered by exactly one of the two tables.
-- Genuinely shared across action=query submodules: these are ApiPageSet's own
-- params (injected by the query-dispatch framework itself, not declared in
-- any individual prop=/list=/meta= submodule's own getAllowedParams()), so
-- they can't be captured per-submodule the way everything else here is.
-- Everything that used to be a generic fallback for a *specific* action or
-- submodule has been removed as that action/submodule got precisely modeled
-- above - keeping them here would let e.g. list=allusers's "aulimit" leak
-- into contexts it doesn't belong to (api_legacy_fields is always allowed,
-- regardless of which action/submodule is actually active).
local api_legacy_fields = {
  titles        = T.nullable(T.string({ max=2048 })),
  pageids       = T.nullable(T.string({ max=2048 })),
  revids        = T.nullable(T.string({ max=2048 })),
  generator     = T.nullable(T.string({ max=64 })),
  redirects     = T.nullable(T.string({ max=8 })),
  converttitles = T.nullable(T.string({ max=8 })),
}

-- Precisely-modeled per-action extra fields. Tier 1: auth/session actions.
-- clientlogin/createaccount/linkaccount/(un)linkaccount/removeauthenticationdata/
-- changeauthenticationdata all delegate to ApiAuthManagerHelper::getStandardParams(),
-- which offers a fixed menu of fields; each caller picks a subset of it
-- (see includes/Api/ApiAuthManagerHelper.php).
local mw_api_actions = {
  login = {
    domain   = T.nullable(T.string({ max=512 })),
    name     = T.nullable(T.string({ max=512 })),
    password = T.nullable(T.string({ max=256 })),  -- sensitive
    token    = T.nullable(T.string({ max=512 })),  -- sensitive; BC allows omitting it
  },
  clientlogin = {
    requests           = T.nullable(T.string({ max=8192 })),  -- serialized AuthenticationRequest[]
    messageformat      = T.nullable(T.string({ max=16, enum={ html=true, wikitext=true, raw=true, none=true } })),
    mergerequestfields = T.nullable(T.string({ max=8 })),
    preservestate      = T.nullable(T.string({ max=8 })),
    returnurl          = T.nullable(T.string({ max=1024 })),
    ["continue"]       = T.nullable(T.string({ max=8 })),
    -- Flat PasswordAuthenticationRequest fields - the plain username/password
    -- login flow MediaWiki's own API help documents as the primary clientlogin
    -- example, distinct from the JS client's 'requests' bundling above.
    username      = T.nullable(T.string({ max=512 })),
    password      = T.nullable(T.string({ max=256 })),  -- sensitive
    logintoken    = T.nullable(T.string({ max=512 })),  -- sensitive
    loginreturnurl = T.nullable(T.string({ max=1024 })),
    logincontinue = T.nullable(T.string({ max=8 })),
    OATHToken     = T.nullable(T.string({ max=32 })),  -- 2FA continuation
  },
  createaccount = {
    requests           = T.nullable(T.string({ max=8192 })),
    messageformat      = T.nullable(T.string({ max=16, enum={ html=true, wikitext=true, raw=true, none=true } })),
    mergerequestfields = T.nullable(T.string({ max=8 })),
    preservestate      = T.nullable(T.string({ max=8 })),
    returnurl          = T.nullable(T.string({ max=1024 })),
    ["continue"]       = T.nullable(T.string({ max=8 })),
    -- Flat fields - see includes/Api/ApiAMCreateAccount.php's own documented example.
    username        = T.nullable(T.string({ max=512 })),
    password        = T.nullable(T.string({ max=256 })),  -- sensitive
    retype          = T.nullable(T.string({ max=256 })),  -- sensitive
    email           = T.nullable(T.string({ max=320 })),
    realname        = T.nullable(T.string({ max=256 })),
    createtoken     = T.nullable(T.string({ max=512 })),  -- sensitive
    createreturnurl = T.nullable(T.string({ max=1024 })),
  },
  linkaccount = {
    requests           = T.nullable(T.string({ max=8192 })),
    messageformat      = T.nullable(T.string({ max=16, enum={ html=true, wikitext=true, raw=true, none=true } })),
    mergerequestfields = T.nullable(T.string({ max=8 })),
    returnurl          = T.nullable(T.string({ max=1024 })),
    ["continue"]       = T.nullable(T.string({ max=8 })),
  },
  unlinkaccount            = { request = T.nullable(T.string({ max=8192 })) },
  changeauthenticationdata = { request = T.nullable(T.string({ max=8192 })) },
  removeauthenticationdata = { request = T.nullable(T.string({ max=8192 })) },
  resetpassword = {
    user  = T.nullable(T.string({ max=256 })),
    email = T.nullable(T.string({ max=320 })),
  },
  validatepassword = {
    password = T.string({ max=256 }),  -- required, sensitive
    user     = T.nullable(T.string({ max=256 })),
    email    = T.nullable(T.string({ max=320 })),
    realname = T.nullable(T.string({ max=256 })),
  },
  checktoken = {
    type = T.string({ max=32, enum={
      csrf=true, watch=true, patrol=true, rollback=true, userrights=true,
      login=true, createaccount=true,
    } }),  -- core's default token-type salts; extensions can register more via a hook (not covered)
    token       = T.string({ max=512 }),  -- sensitive
    maxtokenage = T.nullable(T.number_query({ integer=true })),
  },
  -- acquiretempusername, clearhasmsg, and logout take no parameters at all.
  acquiretempusername = {},
  clearhasmsg          = {},
  logout               = {},

  -- Tiers 2 + 5: mechanically extracted from includes/Api/Api*.php via
  -- extract-mediawiki-api.sh + mw-api-extract/integrate_api_tiers.py.
  -- block (ApiBlock) -- includes/Api/ApiBlock.php
  block = {
    actionrestrictions = T.nullable(T.string({ max=2048 })),  -- dynamic enum from 'array_keys( $this->blockActionInfo->getAllBlockActions() )', left generic
    allowusertalk = T.nullable(T.string({ max=8 })),
    anononly = T.nullable(T.string({ max=8 })),
    autoblock = T.nullable(T.string({ max=8 })),
    expiry = T.nullable(T.string({ max=512 })),
    hidename = T.nullable(T.string({ max=8 })),
    id = T.nullable(T.number_query({ integer=true })),
    namespacerestrictions = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
    newblock = T.nullable(T.string({ max=8 })),
    nocreate = T.nullable(T.string({ max=8 })),
    noemail = T.nullable(T.string({ max=8 })),
    pagerestrictions = T.nullable(T.string({ max=2048 })),
    partial = T.nullable(T.string({ max=8 })),
    reason = T.nullable(T.string({ max=512 })),
    reblock = T.nullable(T.string({ max=8 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
    user = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    userid = T.nullable(T.number_query({ integer=true })),
    watchlistexpiry = T.nullable(T.string({ max=512 })),
    watchuser = T.nullable(T.string({ max=8 })),
  },
  -- changecontentmodel (ApiChangeContentModel) -- includes/Api/ApiChangeContentModel.php
  changecontentmodel = {
    bot = T.nullable(T.string({ max=8 })),
    model = T.string({ max=512 }),  -- dynamic enum from '$modelOptions', left generic
    pageid = T.nullable(T.number_query({ integer=true })),
    summary = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- compare (ApiComparePages) -- includes/Api/ApiComparePages.php
  compare = {
    difftype = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->differenceEngine->getSupportedFormats()', left generic
    prop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: diff, diffsize, rel, ids, title, user, comment, parsedcomment, size, timestamp
    slots = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$slotRoles', left generic
  },
  -- cspreport (ApiCSPReport) -- includes/Api/ApiCSPReport.php
  cspreport = {
    reportonly = T.nullable(T.string({ max=8 })),
    source = T.nullable(T.string({ max=512 })),
  },
  -- delete (ApiDelete) -- includes/Api/ApiDelete.php
  delete = {
    deletetalk = T.nullable(T.string({ max=8 })),
    oldimage = T.nullable(T.string({ max=512 })),
    pageid = T.nullable(T.number_query({ integer=true })),
    reason = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
    unwatch = T.nullable(T.string({ max=512 })),
    watch = T.nullable(T.string({ max=512 })),
  },
  -- edit (ApiEditPage) -- includes/Api/ApiEditPage.php
  edit = {
    appendtext = T.nullable(T.string({ max=1048576 })),
    baserevid = T.nullable(T.number_query({ integer=true })),
    basetimestamp = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
    bot = T.nullable(T.string({ max=8 })),
    contentformat = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getAllContentFormats()', left generic
    contentmodel = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getContentModels()', left generic
    createonly = T.nullable(T.string({ max=8 })),
    md5 = T.nullable(T.string({ max=512 })),
    minor = T.nullable(T.string({ max=8 })),
    nocreate = T.nullable(T.string({ max=8 })),
    notminor = T.nullable(T.string({ max=8 })),
    pageid = T.nullable(T.number_query({ integer=true })),
    prependtext = T.nullable(T.string({ max=1048576 })),
    recreate = T.nullable(T.string({ max=8 })),
    redirect = T.nullable(T.string({ max=8 })),
    section = T.nullable(T.string({ max=512 })),
    sectiontitle = T.nullable(T.string({ max=512 })),
    starttimestamp = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
    summary = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    text = T.nullable(T.string({ max=1048576 })),
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
    undo = T.nullable(T.number_query({ integer=true, min=0 })),
    undoafter = T.nullable(T.number_query({ integer=true, min=0 })),
    unwatch = T.nullable(T.string({ max=512 })),
    watch = T.nullable(T.string({ max=512 })),
  },
  -- emailuser (ApiEmailUser) -- includes/Api/ApiEmailUser.php
  emailuser = {
    ccme = T.nullable(T.string({ max=8 })),
    subject = T.string({ max=512 }),
    target = T.string({ max=512 }),
    text = T.string({ max=1048576 }),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- expandtemplates (ApiExpandTemplates) -- includes/Api/ApiExpandTemplates.php
  expandtemplates = {
    generatexml = T.nullable(T.string({ max=8 })),
    includecomments = T.nullable(T.string({ max=8 })),
    prop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: wikitext, categories, properties, volatile, ttl, modules, jsconfigvars, encodedjsconfigvars, parsetree
    revid = T.nullable(T.number_query({ integer=true })),
    showstrategykeys = T.nullable(T.string({ max=8 })),
    text = T.string({ max=1048576 }),
    title = T.nullable(T.string({ max=512 })),
  },
  -- feedcontributions (ApiFeedContributions) -- includes/Api/ApiFeedContributions.php
  feedcontributions = {
    deletedonly = T.nullable(T.string({ max=8 })),
    feedformat = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$feedFormatNames', left generic
    hideminor = T.nullable(T.string({ max=8 })),
    month = T.nullable(T.number_query({ integer=true })),
    namespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
    newonly = T.nullable(T.string({ max=8 })),
    showsizediff = T.nullable(T.string({ max=512 })),
    tagfilter = T.nullable(T.string({ max=2048 })),  -- dynamic enum from 'array_values( MediaWikiServices::getInstance() ->getChangeTagsStore()->listDefinedTags() )', left generic
    toponly = T.nullable(T.string({ max=8 })),
    user = T.string({ max=512 }),  -- mediawiki type: user
    year = T.nullable(T.number_query({ integer=true })),
  },
  -- feedrecentchanges (ApiFeedRecentChanges) -- includes/Api/ApiFeedRecentChanges.php
  feedrecentchanges = {
    associated = T.nullable(T.string({ max=8 })),
    days = T.nullable(T.number_query({ integer=true, min=1 })),
    feedformat = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$feedFormatNames', left generic
    from = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
    hideanons = T.nullable(T.string({ max=512 })),
    hidebots = T.nullable(T.string({ max=8 })),
    hidecategorization = T.nullable(T.string({ max=8 })),
    hideliu = T.nullable(T.string({ max=8 })),
    hideminor = T.nullable(T.string({ max=8 })),
    hidemyself = T.nullable(T.string({ max=8 })),
    hidepatrolled = T.nullable(T.string({ max=8 })),
    invert = T.nullable(T.string({ max=8 })),
    inverttags = T.nullable(T.string({ max=8 })),
    limit = T.nullable(T.number_query({ integer=true, min=1 })),
    namespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
    showlinkedto = T.nullable(T.string({ max=8 })),
    tagfilter = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
  },
  -- feedwatchlist (ApiFeedWatchlist) -- includes/Api/ApiFeedWatchlist.php
  feedwatchlist = {
    feedformat = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$feedFormatNames', left generic
    hours = T.nullable(T.number_query({ integer=true, min=1, max=72 })),
    linktosections = T.nullable(T.string({ max=8 })),
  },
  -- filerevert (ApiFileRevert) -- includes/Api/ApiFileRevert.php
  filerevert = {
    archivename = T.string({ max=512 }),
    comment = T.nullable(T.string({ max=512 })),
    filename = T.string({ max=512 }),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- help (ApiHelp) -- includes/Api/ApiHelp.php
  help = {
    modules = T.nullable(T.string({ max=2048 })),
    recursivesubmodules = T.nullable(T.string({ max=8 })),
    submodules = T.nullable(T.string({ max=8 })),
    toc = T.nullable(T.string({ max=8 })),
    wrap = T.nullable(T.string({ max=8 })),
  },
  -- imagerotate (ApiImageRotate) -- includes/Api/ApiImageRotate.php
  imagerotate = {
    ['continue'] = T.nullable(T.string({ max=512 })),
    rotation = T.string({ max=3, enum={ ['90']=true, ['180']=true, ['270']=true } }),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- import (ApiImport) -- includes/Api/ApiImport.php
  import = {
    assignknownusers = T.nullable(T.string({ max=8 })),
    fullhistory = T.nullable(T.string({ max=8 })),
    interwikipage = T.nullable(T.string({ max=512 })),
    interwikiprefix = T.nullable(T.string({ max=512 })),
    interwikisource = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->getAllowedImportSources()', left generic
    namespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
    rootpage = T.nullable(T.string({ max=512 })),
    summary = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    templates = T.nullable(T.string({ max=8 })),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
    xml = T.nullable(T.string({ max=512 })),  -- mediawiki type: upload
  },
  -- languagesearch (ApiLanguageSearch) -- includes/Api/ApiLanguageSearch.php
  languagesearch = {
    search = T.string({ max=512 }),
    typos = T.nullable(T.number_query({ integer=true })),
  },
  -- managetags (ApiManageTags) -- includes/Api/ApiManageTags.php
  managetags = {
    ignorewarnings = T.nullable(T.string({ max=8 })),
    operation = T.string({ max=10, enum={ ['create']=true, ['delete']=true, ['activate']=true, ['deactivate']=true } }),
    reason = T.nullable(T.string({ max=512 })),
    tag = T.string({ max=512 }),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- mergehistory (ApiMergeHistory) -- includes/Api/ApiMergeHistory.php
  mergehistory = {
    from = T.nullable(T.string({ max=512 })),
    fromid = T.nullable(T.number_query({ integer=true })),
    reason = T.nullable(T.string({ max=512 })),
    starttimestamp = T.nullable(T.string({ max=512 })),
    timestamp = T.nullable(T.string({ max=512 })),
    to = T.nullable(T.string({ max=512 })),
    toid = T.nullable(T.number_query({ integer=true })),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- move (ApiMove) -- includes/Api/ApiMove.php
  move = {
    from = T.nullable(T.string({ max=512 })),
    fromid = T.nullable(T.number_query({ integer=true })),
    ignorewarnings = T.nullable(T.string({ max=8 })),
    movesubpages = T.nullable(T.string({ max=8 })),
    movetalk = T.nullable(T.string({ max=8 })),
    noredirect = T.nullable(T.string({ max=8 })),
    reason = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    to = T.string({ max=512 }),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- opensearch (ApiOpenSearch) -- includes/Api/ApiOpenSearch.php
  opensearch = {
    format = T.nullable(T.string({ max=6, enum={ ['json']=true, ['jsonfm']=true, ['xml']=true, ['xmlfm']=true } })),
    limit = T.nullable(T.number_query({ integer=true })),
    namespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
    offset = T.nullable(T.number_query({ integer=true })),
    redirects = T.nullable(T.string({ max=7, enum={ ['return']=true, ['resolve']=true } })),
    search = T.string({ max=512 }),
    suggest = T.nullable(T.string({ max=512 })),
    warningsaserror = T.nullable(T.string({ max=8 })),
  },
  -- options (ApiOptions) -- includes/Api/ApiOptions.php
  options = {
    change = T.nullable(T.string({ max=2048 })),
    global = T.nullable(T.string({ max=8, enum={ ['ignore']=true, ['update']=true, ['override']=true, ['create']=true } })),
    optionname = T.nullable(T.string({ max=512 })),
    optionvalue = T.nullable(T.string({ max=512 })),
    reset = T.nullable(T.string({ max=8 })),
    resetkinds = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$optionKinds', left generic
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- paraminfo (ApiParamInfo) -- includes/Api/ApiParamInfo.php
  paraminfo = {
    formatmodules = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$formatmodules', left generic
    helpformat = T.nullable(T.string({ max=8, enum={ ['html']=true, ['wikitext']=true, ['raw']=true, ['none']=true } })),
    mainmodule = T.nullable(T.string({ max=512 })),
    modules = T.nullable(T.string({ max=2048 })),
    pagesetmodule = T.nullable(T.string({ max=512 })),
    querymodules = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$querymodules', left generic
  },
  -- parse (ApiParse) -- includes/Api/ApiParse.php
  parse = {
    contentformat = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getAllContentFormats()', left generic
    contentmodel = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getContentModels()', left generic
    disableeditsection = T.nullable(T.string({ max=8 })),
    disablelimitreport = T.nullable(T.string({ max=8 })),
    disablepp = T.nullable(T.string({ max=512 })),
    disablestylededuplication = T.nullable(T.string({ max=8 })),
    disabletoc = T.nullable(T.string({ max=8 })),
    effectivelanglinks = T.nullable(T.string({ max=512 })),
    generatexml = T.nullable(T.string({ max=512 })),
    oldid = T.nullable(T.number_query({ integer=true })),
    onlypst = T.nullable(T.string({ max=8 })),
    page = T.nullable(T.string({ max=512 })),
    pageid = T.nullable(T.number_query({ integer=true })),
    parser = T.nullable(T.string({ max=7, enum={ ['parsoid']=true, ['default']=true, ['legacy']=true } })),
    parsoid = T.nullable(T.string({ max=8 })),
    preview = T.nullable(T.string({ max=8 })),
    prop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: text, langlinks, categories, categorieshtml, links, templates, images, externallinks, sections, tocdata, revid, displaytitle, subtitle, headhtml, modules, jsconfigvars, encodedjsconfigvars, indicators, iwlinks, wikitext, properties, limitreportdata, limitreporthtml, parsetree, parsewarnings, parsewarningshtml, headitems
    pst = T.nullable(T.string({ max=8 })),
    redirects = T.nullable(T.string({ max=8 })),
    revid = T.nullable(T.number_query({ integer=true })),
    section = T.nullable(T.string({ max=512 })),
    sectionpreview = T.nullable(T.string({ max=8 })),
    sectiontitle = T.nullable(T.string({ max=512 })),
    showstrategykeys = T.nullable(T.string({ max=8 })),
    summary = T.nullable(T.string({ max=512 })),
    text = T.nullable(T.string({ max=1048576 })),
    title = T.nullable(T.string({ max=512 })),
    usearticle = T.nullable(T.string({ max=8 })),
    useskin = T.nullable(T.string({ max=512 })),  -- dynamic enum from 'array_keys( $this->skinFactory->getInstalledSkins() )', left generic
    wrapoutputclass = T.nullable(T.string({ max=512 })),
  },
  -- patrol (ApiPatrol) -- includes/Api/ApiPatrol.php
  patrol = {
    rcid = T.nullable(T.number_query({ integer=true })),
    revid = T.nullable(T.number_query({ integer=true })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- protect (ApiProtect) -- includes/Api/ApiProtect.php
  protect = {
    cascade = T.nullable(T.string({ max=8 })),
    expiry = T.nullable(T.string({ max=2048 })),
    pageid = T.nullable(T.number_query({ integer=true })),
    protections = T.string({ max=2048 }),
    reason = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
    watch = T.nullable(T.string({ max=512 })),
  },
  -- purge (ApiPurge) -- includes/Api/ApiPurge.php
  purge = {
    ['continue'] = T.nullable(T.string({ max=512 })),
    forcelinkupdate = T.nullable(T.string({ max=8 })),
    forcerecursivelinkupdate = T.nullable(T.string({ max=8 })),
  },
  -- query (ApiQuery) -- includes/Api/ApiQuery.php
  query = {
    ['continue'] = T.nullable(T.string({ max=512 })),
    export = T.nullable(T.string({ max=8 })),
    exportnowrap = T.nullable(T.string({ max=8 })),
    exportschema = T.nullable(T.string({ max=512 })),  -- dynamic enum from 'XmlDumpWriter::$supportedSchemas', left generic
    indexpageids = T.nullable(T.string({ max=8 })),
    iwurl = T.nullable(T.string({ max=8 })),
    list = T.nullable(T.string({ max=2048 })),  -- mediawiki type: submodule
    meta = T.nullable(T.string({ max=2048 })),  -- mediawiki type: submodule
    prop = T.nullable(T.string({ max=2048 })),  -- mediawiki type: submodule
    rawcontinue = T.nullable(T.string({ max=8 })),
  },
  -- revisiondelete (ApiRevisionDelete) -- includes/Api/ApiRevisionDelete.php
  revisiondelete = {
    hide = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: content, comment, user
    ids = T.string({ max=2048 }),
    reason = T.nullable(T.string({ max=512 })),
    show = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: content, comment, user
    suppress = T.nullable(T.string({ max=8, enum={ ['yes']=true, ['no']=true, ['nochange']=true } })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    target = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
    ['type'] = T.string({ max=512 }),  -- dynamic enum from 'RevisionDeleter::getTypes()', left generic
  },
  -- rollback (ApiRollback) -- includes/Api/ApiRollback.php
  rollback = {
    markbot = T.nullable(T.string({ max=8 })),
    pageid = T.nullable(T.number_query({ integer=true })),
    summary = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
    user = T.string({ max=512 }),  -- mediawiki type: user
  },
  -- rsd (ApiRsd) -- includes/Api/ApiRsd.php
  rsd = {

  },
  -- setnotificationtimestamp (ApiSetNotificationTimestamp) -- includes/Api/ApiSetNotificationTimestamp.php
  setnotificationtimestamp = {
    ['continue'] = T.nullable(T.string({ max=512 })),
    entirewatchlist = T.nullable(T.string({ max=8 })),
    newerthanrevid = T.nullable(T.number_query({ integer=true })),
    timestamp = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
    torevid = T.nullable(T.number_query({ integer=true })),
  },
  -- setpagelanguage (ApiSetPageLanguage) -- includes/Api/ApiSetPageLanguage.php
  setpagelanguage = {
    lang = T.string({ max=7, enum={ ['default']=true } }),
    pageid = T.nullable(T.number_query({ integer=true })),
    reason = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- stashedit (ApiStashEdit) -- includes/Api/ApiStashEdit.php
  stashedit = {
    baserevid = T.number_query({ integer=true }),
    contentformat = T.string({ max=512 }),  -- dynamic enum from '$this->contentHandlerFactory->getAllContentFormats()', left generic
    contentmodel = T.string({ max=512 }),  -- dynamic enum from '$this->contentHandlerFactory->getContentModels()', left generic
    section = T.nullable(T.string({ max=512 })),
    sectiontitle = T.nullable(T.string({ max=512 })),
    stashedtexthash = T.nullable(T.string({ max=512 })),
    summary = T.nullable(T.string({ max=512 })),
    text = T.nullable(T.string({ max=1048576 })),
    title = T.string({ max=512 }),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- tag (ApiTag) -- includes/Api/ApiTag.php
  tag = {
    add = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    logid = T.nullable(T.number_query({ integer=true })),
    rcid = T.nullable(T.number_query({ integer=true })),
    reason = T.nullable(T.string({ max=512 })),
    remove = T.nullable(T.string({ max=2048 })),
    revid = T.nullable(T.number_query({ integer=true })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
  },
  -- unblock (ApiUnblock) -- includes/Api/ApiUnblock.php
  unblock = {
    id = T.nullable(T.number_query({ integer=true })),
    reason = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
    user = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    userid = T.nullable(T.number_query({ integer=true })),
    watchlistexpiry = T.nullable(T.string({ max=512 })),
    watchuser = T.nullable(T.string({ max=8 })),
  },
  -- undelete (ApiUndelete) -- includes/Api/ApiUndelete.php
  undelete = {
    fileids = T.nullable(T.number_query({ integer=true })),
    reason = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    timestamps = T.nullable(T.string({ max=2048 })),  -- mediawiki type: timestamp
    title = T.string({ max=512 }),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
    undeletetalk = T.nullable(T.string({ max=8 })),
  },
  -- upload (ApiUpload) -- includes/Api/ApiUpload.php
  upload = {
    async = T.nullable(T.string({ max=8 })),
    checkstatus = T.nullable(T.string({ max=8 })),
    chunk = T.nullable(T.string({ max=512 })),  -- mediawiki type: upload
    comment = T.nullable(T.string({ max=512 })),
    file = T.nullable(T.string({ max=512 })),  -- mediawiki type: upload
    filekey = T.nullable(T.string({ max=512 })),
    filename = T.nullable(T.string({ max=512 })),
    filesize = T.nullable(T.number_query({ integer=true, min=0 })),
    ignorewarnings = T.nullable(T.string({ max=8 })),
    offset = T.nullable(T.number_query({ integer=true, min=0 })),
    sessionkey = T.nullable(T.string({ max=512 })),
    stash = T.nullable(T.string({ max=8 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    text = T.nullable(T.string({ max=1048576 })),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
    url = T.nullable(T.string({ max=512 })),
    watch = T.nullable(T.string({ max=512 })),
  },
  -- userrights (ApiUserrights) -- includes/Api/ApiUserrights.php
  userrights = {
    add = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$allGroups', left generic
    expiry = T.nullable(T.string({ max=2048 })),
    reason = T.nullable(T.string({ max=512 })),
    remove = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$allGroups', left generic
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    token = T.nullable(T.string({ max=512 })),
    user = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    userid = T.nullable(T.number_query({ integer=true })),
    watchlistexpiry = T.nullable(T.string({ max=512 })),
    watchuser = T.nullable(T.string({ max=8 })),
  },
  -- watch (ApiWatch) -- includes/Api/ApiWatch.php
  watch = {
    ['continue'] = T.nullable(T.string({ max=512 })),
    expiry = T.nullable(T.string({ max=512 })),
    labels = T.nullable(T.number_query({ integer=true })),
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),  -- sensitive; injected by ApiBase::getFinalParams() via needsToken(), not declared in getAllowedParams()
    unwatch = T.nullable(T.string({ max=8 })),
  },
}

-- action=query submodules, looked up by name from prop=/list=/meta= (each
-- pipe-separated and multi-valued) rather than from `action` directly - see
-- resolve_query_submodule_fields() below. Mechanically extracted the same way.
local mw_query_submodules = {
  prop = {
    -- categories (ApiQueryCategories) -- includes/Api/ApiQueryCategories.php
    categories = {
      clcategories = T.nullable(T.string({ max=2048 })),
      clcontinue = T.nullable(T.string({ max=512 })),
      cldir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      cllimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      clprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: sortkey, timestamp, hidden
      clshow = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: hidden, !hidden
    },
    -- categoryinfo (ApiQueryCategoryInfo) -- includes/Api/ApiQueryCategoryInfo.php
    categoryinfo = {
      cicontinue = T.nullable(T.string({ max=512 })),
    },
    -- contributors (ApiQueryContributors) -- includes/Api/ApiQueryContributors.php
    contributors = {
      pccontinue = T.nullable(T.string({ max=512 })),
      pcexcludegroup = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$userGroups', left generic
      pcexcluderights = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$userRights', left generic
      pcgroup = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$userGroups', left generic
      pclimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      pcrights = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$userRights', left generic
    },
    -- deletedrevisions (ApiQueryDeletedRevisions) -- includes/Api/ApiQueryDeletedRevisions.php
    deletedrevisions = {
      drvcontentformat = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getAllContentFormats()', left generic
      ['drvcontentformat-{slot}'] = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getAllContentFormats()', left generic
      drvcontinue = T.nullable(T.string({ max=512 })),
      drvdiffto = T.nullable(T.string({ max=512 })),
      drvdifftotext = T.nullable(T.string({ max=512 })),
      drvdifftotextpst = T.nullable(T.string({ max=512 })),
      drvdir = T.nullable(T.string({ max=5, enum={ ['newer']=true, ['older']=true } })),
      drvend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      drvexcludeuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
      drvexpandtemplates = T.nullable(T.string({ max=512 })),
      drvgeneratexml = T.nullable(T.string({ max=512 })),
      drvlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      drvparse = T.nullable(T.string({ max=512 })),
      drvprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, flags, timestamp, user, userid, size, slotsize, sha1, slotsha1, contentmodel, comment, parsedcomment, content, tags, roles, parsetree
      drvsection = T.nullable(T.string({ max=512 })),
      drvslots = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$slotRoles', left generic
      drvstart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      drvtag = T.nullable(T.string({ max=512 })),
      drvuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    },
    -- duplicatefiles (ApiQueryDuplicateFiles) -- includes/Api/ApiQueryDuplicateFiles.php
    duplicatefiles = {
      dfcontinue = T.nullable(T.string({ max=512 })),
      dfdir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      dflimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      dflocalonly = T.nullable(T.string({ max=8 })),
    },
    -- extlinks (ApiQueryExternalLinks) -- includes/Api/ApiQueryExternalLinks.php
    extlinks = {
      elcontinue = T.nullable(T.string({ max=512 })),
      elexpandurl = T.nullable(T.string({ max=8 })),
      ellimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      elprotocol = T.nullable(T.string({ max=512 })),  -- dynamic enum from 'LinkFilter::prepareProtocols()', left generic
      elquery = T.nullable(T.string({ max=512 })),
    },
    -- fileusage (ApiQueryBacklinksprop) -- includes/Api/ApiQueryBacklinksprop.php
    fileusage = {
      fucontinue = T.nullable(T.string({ max=512 })),
      fulimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      funamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      fuprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: pageid, title
      fushow = T.nullable(T.string({ max=512 })),
    },
    -- imageinfo (ApiQueryImageInfo) -- includes/Api/ApiQueryImageInfo.php
    imageinfo = {
      iibadfilecontexttitle = T.nullable(T.string({ max=512 })),
      iicontinue = T.nullable(T.string({ max=512 })),
      iiend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      iiextmetadatafilter = T.nullable(T.string({ max=2048 })),
      iiextmetadatalanguage = T.nullable(T.string({ max=512 })),
      iiextmetadatamultilang = T.nullable(T.string({ max=8 })),
      iilimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      iilocalonly = T.nullable(T.string({ max=8 })),
      iimetadataversion = T.nullable(T.string({ max=512 })),
      iiprop = T.nullable(T.string({ max=2048 })),  -- dynamic enum from 'static::getPropertyNames()', left generic
      iistart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      iiurlheight = T.nullable(T.number_query({ integer=true })),
      iiurlparam = T.nullable(T.string({ max=512 })),
      iiurlwidth = T.nullable(T.number_query({ integer=true })),
    },
    -- images (ApiQueryImages) -- includes/Api/ApiQueryImages.php
    images = {
      imcontinue = T.nullable(T.string({ max=512 })),
      imdir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      imimages = T.nullable(T.string({ max=2048 })),
      imlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
    },
    -- info (ApiQueryInfo) -- includes/Api/ApiQueryInfo.php
    info = {
      incontinue = T.nullable(T.string({ max=512 })),
      indefaultlinkcaption = T.nullable(T.string({ max=8 })),
      ineditintrocustom = T.nullable(T.string({ max=512 })),
      ineditintroskip = T.nullable(T.string({ max=2048 })),
      ineditintrostyle = T.nullable(T.string({ max=10, enum={ ['lessframes']=true, ['moreframes']=true } })),
      inlinkcontext = T.nullable(T.string({ max=512 })),
      inpreloadcustom = T.nullable(T.string({ max=512 })),
      inpreloadnewsection = T.nullable(T.string({ max=8 })),
      inpreloadparams = T.nullable(T.string({ max=2048 })),
      inprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: protection, talkid, watched, watchlistlabels, watchers, visitingwatchers, notificationtimestamp, subjectid, associatedpage, url, readable, preload, preloadcontent, editintro, displaytitle, varianttitles, linkclasses
      intestactions = T.nullable(T.string({ max=2048 })),
      intestactionsautocreate = T.nullable(T.string({ max=8 })),
      intestactionsdetail = T.nullable(T.string({ max=7, enum={ ['boolean']=true, ['full']=true, ['quick']=true } })),
    },
    -- iwlinks (ApiQueryIWLinks) -- includes/Api/ApiQueryIWLinks.php
    iwlinks = {
      iwcontinue = T.nullable(T.string({ max=512 })),
      iwdir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      iwlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      iwprefix = T.nullable(T.string({ max=512 })),
      iwprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: url
      iwtitle = T.nullable(T.string({ max=512 })),
      iwurl = T.nullable(T.string({ max=512 })),
    },
    -- langlinks (ApiQueryLangLinks) -- includes/Api/ApiQueryLangLinks.php
    langlinks = {
      llcontinue = T.nullable(T.string({ max=512 })),
      lldir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      llinlanguagecode = T.nullable(T.string({ max=512 })),
      lllang = T.nullable(T.string({ max=512 })),
      lllimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      llprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: url, langname, autonym
      lltitle = T.nullable(T.string({ max=512 })),
      llurl = T.nullable(T.string({ max=512 })),
    },
    -- links (ApiQueryLinks) -- includes/Api/ApiQueryLinks.php
    links = {
      plcontinue = T.nullable(T.string({ max=512 })),
      pldir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      pllimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      plnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
    },
    -- linkshere (ApiQueryBacklinksprop) -- includes/Api/ApiQueryBacklinksprop.php
    linkshere = {
      lhcontinue = T.nullable(T.string({ max=512 })),
      lhlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      lhnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      lhprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: pageid, title
      lhshow = T.nullable(T.string({ max=512 })),
    },
    -- pageprops (ApiQueryPageProps) -- includes/Api/ApiQueryPageProps.php
    pageprops = {
      ppcontinue = T.nullable(T.string({ max=512 })),
      ppprop = T.nullable(T.string({ max=2048 })),
    },
    -- redirects (ApiQueryBacklinksprop) -- includes/Api/ApiQueryBacklinksprop.php
    redirects = {
      rdcontinue = T.nullable(T.string({ max=512 })),
      rdlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      rdnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      rdprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: pageid, title
      rdshow = T.nullable(T.string({ max=512 })),
    },
    -- revisions (ApiQueryRevisions) -- includes/Api/ApiQueryRevisions.php
    revisions = {
      rvcontentformat = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getAllContentFormats()', left generic
      ['rvcontentformat-{slot}'] = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getAllContentFormats()', left generic
      rvcontinue = T.nullable(T.string({ max=512 })),
      rvdiffto = T.nullable(T.string({ max=512 })),
      rvdifftotext = T.nullable(T.string({ max=512 })),
      rvdifftotextpst = T.nullable(T.string({ max=512 })),
      rvdir = T.nullable(T.string({ max=5, enum={ ['newer']=true, ['older']=true } })),
      rvend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      rvendid = T.nullable(T.number_query({ integer=true })),
      rvexcludeuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
      rvexpandtemplates = T.nullable(T.string({ max=512 })),
      rvgeneratexml = T.nullable(T.string({ max=512 })),
      rvlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      rvparse = T.nullable(T.string({ max=512 })),
      rvprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, flags, timestamp, user, userid, size, slotsize, sha1, slotsha1, contentmodel, comment, parsedcomment, content, tags, roles, parsetree
      rvsection = T.nullable(T.string({ max=512 })),
      rvslots = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$slotRoles', left generic
      rvstart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      rvstartid = T.nullable(T.number_query({ integer=true })),
      rvtag = T.nullable(T.string({ max=512 })),
      rvuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    },
    -- stashimageinfo (ApiQueryStashImageInfo) -- includes/Api/ApiQueryStashImageInfo.php
    stashimageinfo = {
      siifilekey = T.nullable(T.string({ max=2048 })),
      siiprop = T.nullable(T.string({ max=2048 })),  -- dynamic enum from 'self::getPropertyNames()', left generic
      siisessionkey = T.nullable(T.string({ max=2048 })),
      siiurlheight = T.nullable(T.number_query({ integer=true })),
      siiurlparam = T.nullable(T.string({ max=512 })),
      siiurlwidth = T.nullable(T.number_query({ integer=true })),
    },
    -- templates (ApiQueryLinks) -- includes/Api/ApiQueryLinks.php
    templates = {
      tlcontinue = T.nullable(T.string({ max=512 })),
      tldir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      tllimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      tlnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
    },
    -- transcludedin (ApiQueryBacklinksprop) -- includes/Api/ApiQueryBacklinksprop.php
    transcludedin = {
      ticontinue = T.nullable(T.string({ max=512 })),
      tilimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      tinamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      tiprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: pageid, title
      tishow = T.nullable(T.string({ max=512 })),
    },
  },
  list = {
    -- allcategories (ApiQueryAllCategories) -- includes/Api/ApiQueryAllCategories.php
    allcategories = {
      accontinue = T.nullable(T.string({ max=512 })),
      acdir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      acfrom = T.nullable(T.string({ max=512 })),
      aclimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      acmax = T.nullable(T.number_query({ integer=true })),
      acmin = T.nullable(T.number_query({ integer=true })),
      acprefix = T.nullable(T.string({ max=512 })),
      acprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: size, hidden
      acto = T.nullable(T.string({ max=512 })),
    },
    -- alldeletedrevisions (ApiQueryAllDeletedRevisions) -- includes/Api/ApiQueryAllDeletedRevisions.php
    alldeletedrevisions = {
      adrcontentformat = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getAllContentFormats()', left generic
      ['adrcontentformat-{slot}'] = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getAllContentFormats()', left generic
      adrcontinue = T.nullable(T.string({ max=512 })),
      adrdiffto = T.nullable(T.string({ max=512 })),
      adrdifftotext = T.nullable(T.string({ max=512 })),
      adrdifftotextpst = T.nullable(T.string({ max=512 })),
      adrdir = T.nullable(T.string({ max=5, enum={ ['newer']=true, ['older']=true } })),
      adrend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      adrexcludeuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
      adrexpandtemplates = T.nullable(T.string({ max=512 })),
      adrfrom = T.nullable(T.string({ max=512 })),
      adrgeneratetitles = T.nullable(T.string({ max=512 })),
      adrgeneratexml = T.nullable(T.string({ max=512 })),
      adrlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      adrnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      adrparse = T.nullable(T.string({ max=512 })),
      adrprefix = T.nullable(T.string({ max=512 })),
      adrprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, flags, timestamp, user, userid, size, slotsize, sha1, slotsha1, contentmodel, comment, parsedcomment, content, tags, roles, parsetree
      adrsection = T.nullable(T.string({ max=512 })),
      adrslots = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$slotRoles', left generic
      adrstart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      adrtag = T.nullable(T.string({ max=512 })),
      adrto = T.nullable(T.string({ max=512 })),
      adruser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    },
    -- allfileusages (ApiQueryAllLinks) -- includes/Api/ApiQueryAllLinks.php
    allfileusages = {
      afcontinue = T.nullable(T.string({ max=512 })),
      afdir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      affrom = T.nullable(T.string({ max=512 })),
      aflimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      afnamespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
      afprefix = T.nullable(T.string({ max=512 })),
      afprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, title
      afto = T.nullable(T.string({ max=512 })),
      afunique = T.nullable(T.string({ max=8 })),
    },
    -- allimages (ApiQueryAllImages) -- includes/Api/ApiQueryAllImages.php
    allimages = {
      aicontinue = T.nullable(T.string({ max=512 })),
      aidir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true, ['newer']=true, ['older']=true } })),
      aiend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      aifilterbots = T.nullable(T.string({ max=6, enum={ ['all']=true, ['bots']=true, ['nobots']=true } })),
      aifrom = T.nullable(T.string({ max=512 })),
      ailimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      aimaxsize = T.nullable(T.number_query({ integer=true })),
      aimime = T.nullable(T.string({ max=2048 })),
      aiminsize = T.nullable(T.number_query({ integer=true })),
      aiprefix = T.nullable(T.string({ max=512 })),
      aiprop = T.nullable(T.string({ max=2048 })),  -- dynamic enum from 'ApiQueryImageInfo::getPropertyNames( self::PROPERTY_FILTER )', left generic
      aisha1 = T.nullable(T.string({ max=512 })),
      aisha1base36 = T.nullable(T.string({ max=512 })),
      aisort = T.nullable(T.string({ max=9, enum={ ['name']=true, ['timestamp']=true } })),
      aistart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      aito = T.nullable(T.string({ max=512 })),
      aiuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    },
    -- alllinks (ApiQueryAllLinks) -- includes/Api/ApiQueryAllLinks.php
    alllinks = {
      alcontinue = T.nullable(T.string({ max=512 })),
      aldir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      alfrom = T.nullable(T.string({ max=512 })),
      allimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      alnamespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
      alprefix = T.nullable(T.string({ max=512 })),
      alprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, title
      alto = T.nullable(T.string({ max=512 })),
      alunique = T.nullable(T.string({ max=8 })),
    },
    -- allpages (ApiQueryAllPages) -- includes/Api/ApiQueryAllPages.php
    allpages = {
      apcontinue = T.nullable(T.string({ max=512 })),
      apdir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      apfilterlanglinks = T.nullable(T.string({ max=16, enum={ ['withlanglinks']=true, ['withoutlanglinks']=true, ['all']=true } })),
      apfilterredir = T.nullable(T.string({ max=12, enum={ ['all']=true, ['redirects']=true, ['nonredirects']=true } })),
      apfrom = T.nullable(T.string({ max=512 })),
      aplimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      apmaxsize = T.nullable(T.number_query({ integer=true })),
      apminsize = T.nullable(T.number_query({ integer=true })),
      apnamespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
      apprefix = T.nullable(T.string({ max=512 })),
      apprexpiry = T.nullable(T.string({ max=10, enum={ ['indefinite']=true, ['definite']=true, ['all']=true } })),
      apprfiltercascade = T.nullable(T.string({ max=12, enum={ ['cascading']=true, ['noncascading']=true, ['all']=true } })),
      apprlevel = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$this->getConfig()->get( MainConfigNames::RestrictionLevels )', left generic
      apprtype = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$this->restrictionStore->listAllRestrictionTypes( true )', left generic
      apto = T.nullable(T.string({ max=512 })),
    },
    -- allredirects (ApiQueryAllLinks) -- includes/Api/ApiQueryAllLinks.php
    allredirects = {
      arcontinue = T.nullable(T.string({ max=512 })),
      ardir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      arfrom = T.nullable(T.string({ max=512 })),
      arlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      arnamespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
      arprefix = T.nullable(T.string({ max=512 })),
      arprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, title
      arto = T.nullable(T.string({ max=512 })),
      arunique = T.nullable(T.string({ max=8 })),
    },
    -- allrevisions (ApiQueryAllRevisions) -- includes/Api/ApiQueryAllRevisions.php
    allrevisions = {
      arvcontentformat = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getAllContentFormats()', left generic
      ['arvcontentformat-{slot}'] = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getAllContentFormats()', left generic
      arvcontinue = T.nullable(T.string({ max=512 })),
      arvdiffto = T.nullable(T.string({ max=512 })),
      arvdifftotext = T.nullable(T.string({ max=512 })),
      arvdifftotextpst = T.nullable(T.string({ max=512 })),
      arvdir = T.nullable(T.string({ max=5, enum={ ['newer']=true, ['older']=true } })),
      arvend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      arvexcludeuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
      arvexpandtemplates = T.nullable(T.string({ max=512 })),
      arvgeneratetitles = T.nullable(T.string({ max=512 })),
      arvgeneratexml = T.nullable(T.string({ max=512 })),
      arvlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      arvnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      arvparse = T.nullable(T.string({ max=512 })),
      arvprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, flags, timestamp, user, userid, size, slotsize, sha1, slotsha1, contentmodel, comment, parsedcomment, content, tags, roles, parsetree
      arvsection = T.nullable(T.string({ max=512 })),
      arvslots = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$slotRoles', left generic
      arvstart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      arvuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    },
    -- alltransclusions (ApiQueryAllLinks) -- includes/Api/ApiQueryAllLinks.php
    alltransclusions = {
      atcontinue = T.nullable(T.string({ max=512 })),
      atdir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      atfrom = T.nullable(T.string({ max=512 })),
      atlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      atnamespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
      atprefix = T.nullable(T.string({ max=512 })),
      atprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, title
      atto = T.nullable(T.string({ max=512 })),
      atunique = T.nullable(T.string({ max=8 })),
    },
    -- allusers (ApiQueryAllUsers) -- includes/Api/ApiQueryAllUsers.php
    allusers = {
      auactiveusers = T.nullable(T.string({ max=512 })),
      auattachedwiki = T.nullable(T.string({ max=512 })),
      audir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      auexcludegroup = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$userGroups', left generic
      auexcludenamed = T.nullable(T.string({ max=8 })),
      auexcludetemp = T.nullable(T.string({ max=8 })),
      aufrom = T.nullable(T.string({ max=512 })),
      augroup = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$userGroups', left generic
      aulimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      auprefix = T.nullable(T.string({ max=512 })),
      auprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: blockinfo, groups, implicitgroups, rights, editcount, registration, centralids, tempexpired
      aurights = T.nullable(T.string({ max=2048 })),  -- dynamic enum from 'array_unique( array_merge( $this->getPermissionManager()->getAllPermissions(), $this->getPermissionManager()->getImplicitRights() ) )', left generic
      auto = T.nullable(T.string({ max=512 })),
      auwitheditsonly = T.nullable(T.string({ max=8 })),
    },
    -- backlinks (ApiQueryBacklinks) -- includes/Api/ApiQueryBacklinks.php
    backlinks = {
      blcontinue = T.nullable(T.string({ max=512 })),
      bldir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      blfilterredir = T.nullable(T.string({ max=12, enum={ ['all']=true, ['redirects']=true, ['nonredirects']=true } })),
      bllimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      blnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      blpageid = T.nullable(T.number_query({ integer=true })),
      bltitle = T.nullable(T.string({ max=512 })),
    },
    -- blocks (ApiQueryBlocks) -- includes/Api/ApiQueryBlocks.php
    blocks = {
      bkcontinue = T.nullable(T.string({ max=512 })),
      bkdir = T.nullable(T.string({ max=5, enum={ ['newer']=true, ['older']=true } })),
      bkend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      bkids = T.nullable(T.number_query({ integer=true })),
      bkip = T.nullable(T.string({ max=512 })),
      bklimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      bkprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: id, user, userid, by, byid, timestamp, expiry, reason, parsedreason, range, flags, restrictions
      bkshow = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: account, !account, temp, !temp, ip, !ip, range, !range
      bkstart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      bkusers = T.nullable(T.string({ max=2048 })),  -- mediawiki type: user
    },
    -- categorymembers (ApiQueryCategoryMembers) -- includes/Api/ApiQueryCategoryMembers.php
    categorymembers = {
      cmcontinue = T.nullable(T.string({ max=512 })),
      cmdir = T.nullable(T.string({ max=10, enum={ ['asc']=true, ['desc']=true, ['ascending']=true, ['descending']=true, ['newer']=true, ['older']=true } })),
      cmend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      cmendhexsortkey = T.nullable(T.string({ max=512 })),
      cmendsortkey = T.nullable(T.string({ max=512 })),
      cmendsortkeyprefix = T.nullable(T.string({ max=512 })),
      cmlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      cmnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      cmpageid = T.nullable(T.number_query({ integer=true })),
      cmprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, title, sortkey, sortkeyprefix, type, timestamp
      cmsort = T.nullable(T.string({ max=9, enum={ ['sortkey']=true, ['timestamp']=true } })),
      cmstart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      cmstarthexsortkey = T.nullable(T.string({ max=512 })),
      cmstartsortkey = T.nullable(T.string({ max=512 })),
      cmstartsortkeyprefix = T.nullable(T.string({ max=512 })),
      cmtitle = T.nullable(T.string({ max=512 })),
      cmtype = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: page, subcat, file
    },
    -- codexicons (ApiQueryCodexIcons) -- includes/Api/ApiQueryCodexIcons.php
    codexicons = {
      names = T.string({ max=2048 }),  -- dynamic enum from 'array_keys( CodexModule::getIcons( null, $this->getConfig() ) )', left generic
    },
    -- deletedrevs (ApiQueryDeletedrevs) -- includes/Api/ApiQueryDeletedrevs.php
    deletedrevs = {
      drcontinue = T.nullable(T.string({ max=512 })),
      drdir = T.nullable(T.string({ max=5, enum={ ['newer']=true, ['older']=true } })),
      drend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      drexcludeuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
      drfrom = T.nullable(T.string({ max=512 })),
      drlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      drnamespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
      drprefix = T.nullable(T.string({ max=512 })),
      drprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: revid, parentid, user, userid, comment, parsedcomment, minor, len, sha1, content, token, tags
      drstart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      drtag = T.nullable(T.string({ max=512 })),
      drto = T.nullable(T.string({ max=512 })),
      drunique = T.nullable(T.string({ max=512 })),
      druser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    },
    -- embeddedin (ApiQueryBacklinks) -- includes/Api/ApiQueryBacklinks.php
    embeddedin = {
      eicontinue = T.nullable(T.string({ max=512 })),
      eidir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      eifilterredir = T.nullable(T.string({ max=12, enum={ ['all']=true, ['redirects']=true, ['nonredirects']=true } })),
      eilimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      einamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      eipageid = T.nullable(T.number_query({ integer=true })),
      eititle = T.nullable(T.string({ max=512 })),
    },
    -- exturlusage (ApiQueryExtLinksUsage) -- includes/Api/ApiQueryExtLinksUsage.php
    exturlusage = {
      eucontinue = T.nullable(T.string({ max=512 })),
      euexpandurl = T.nullable(T.string({ max=8 })),
      eulimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      eunamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      euprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, title, url
      euprotocol = T.nullable(T.string({ max=512 })),  -- dynamic enum from 'LinkFilter::prepareProtocols()', left generic
      euquery = T.nullable(T.string({ max=512 })),
    },
    -- filearchive (ApiQueryFilearchive) -- includes/Api/ApiQueryFilearchive.php
    filearchive = {
      facontinue = T.nullable(T.string({ max=512 })),
      fadir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      fafrom = T.nullable(T.string({ max=512 })),
      falimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      faprefix = T.nullable(T.string({ max=512 })),
      faprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: sha1, timestamp, user, size, dimensions, description, parseddescription, mime, mediatype, metadata, bitdepth, archivename
      fasha1 = T.nullable(T.string({ max=512 })),
      fasha1base36 = T.nullable(T.string({ max=512 })),
      fato = T.nullable(T.string({ max=512 })),
    },
    -- imageusage (ApiQueryBacklinks) -- includes/Api/ApiQueryBacklinks.php
    imageusage = {
      iucontinue = T.nullable(T.string({ max=512 })),
      iudir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      iufilterredir = T.nullable(T.string({ max=12, enum={ ['all']=true, ['redirects']=true, ['nonredirects']=true } })),
      iulimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      iunamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      iupageid = T.nullable(T.number_query({ integer=true })),
      iutitle = T.nullable(T.string({ max=512 })),
    },
    -- iwbacklinks (ApiQueryIWBacklinks) -- includes/Api/ApiQueryIWBacklinks.php
    iwbacklinks = {
      iwblcontinue = T.nullable(T.string({ max=512 })),
      iwbldir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      iwbllimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      iwblprefix = T.nullable(T.string({ max=512 })),
      iwblprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: iwprefix, iwtitle
      iwbltitle = T.nullable(T.string({ max=512 })),
    },
    -- langbacklinks (ApiQueryLangBacklinks) -- includes/Api/ApiQueryLangBacklinks.php
    langbacklinks = {
      lblcontinue = T.nullable(T.string({ max=512 })),
      lbldir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      lbllang = T.nullable(T.string({ max=512 })),
      lbllimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      lblprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: lllang, lltitle
      lbltitle = T.nullable(T.string({ max=512 })),
    },
    -- logevents (ApiQueryLogEvents) -- includes/Api/ApiQueryLogEvents.php
    logevents = {
      leaction = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$logActions', left generic
      lecontinue = T.nullable(T.string({ max=512 })),
      ledir = T.nullable(T.string({ max=5, enum={ ['newer']=true, ['older']=true } })),
      leend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      leids = T.nullable(T.number_query({ integer=true })),
      lelimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      lenamespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
      leprefix = T.nullable(T.string({ max=512 })),
      leprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, title, type, user, userid, timestamp, comment, parsedcomment, details, tags
      lestart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      letag = T.nullable(T.string({ max=512 })),
      letitle = T.nullable(T.string({ max=512 })),
      letype = T.nullable(T.string({ max=512 })),  -- dynamic enum from 'LogPage::validTypes()', left generic
      leuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    },
    -- mystashedfiles (ApiQueryMyStashedFiles) -- includes/Api/ApiQueryMyStashedFiles.php
    mystashedfiles = {
      msfcontinue = T.nullable(T.string({ max=512 })),
      msflimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      msfprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: size, type
    },
    -- pagepropnames (ApiQueryPagePropNames) -- includes/Api/ApiQueryPagePropNames.php
    pagepropnames = {
      ppncontinue = T.nullable(T.string({ max=512 })),
      ppnlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
    },
    -- pageswithprop (ApiQueryPagesWithProp) -- includes/Api/ApiQueryPagesWithProp.php
    pageswithprop = {
      pwpcontinue = T.nullable(T.string({ max=512 })),
      pwpdir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      pwplimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      pwpprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, title, value
      pwppropname = T.string({ max=512 }),
    },
    -- prefixsearch (ApiQueryPrefixSearch) -- includes/Api/ApiQueryPrefixSearch.php
    prefixsearch = {
      pslimit = T.nullable(T.number_query({ integer=true })),
      psnamespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
      psoffset = T.nullable(T.number_query({ integer=true })),
      pssearch = T.string({ max=512 }),
    },
    -- protectedtitles (ApiQueryProtectedTitles) -- includes/Api/ApiQueryProtectedTitles.php
    protectedtitles = {
      ptcontinue = T.nullable(T.string({ max=512 })),
      ptdir = T.nullable(T.string({ max=5, enum={ ['newer']=true, ['older']=true } })),
      ptend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      ptlevel = T.nullable(T.string({ max=2048 })),  -- dynamic enum from "array_diff( $this->getConfig()->get( MainConfigNames::RestrictionLevels ), [ '' ] )", left generic
      ptlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      ptnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      ptprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: timestamp, user, userid, comment, parsedcomment, expiry, level
      ptstart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
    },
    -- querypage (ApiQueryQueryPage) -- includes/Api/ApiQueryQueryPage.php
    querypage = {
      qplimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      qpoffset = T.nullable(T.string({ max=512 })),
      qppage = T.string({ max=512 }),  -- dynamic enum from '$this->queryPages', left generic
    },
    -- random (ApiQueryRandom) -- includes/Api/ApiQueryRandom.php
    random = {
      rncontentmodel = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->contentHandlerFactory->getContentModels()', left generic
      rncontinue = T.nullable(T.string({ max=512 })),
      rnfilterredir = T.nullable(T.string({ max=12, enum={ ['all']=true, ['redirects']=true, ['nonredirects']=true } })),
      rnlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      rnmaxsize = T.nullable(T.number_query({ integer=true })),
      rnminsize = T.nullable(T.number_query({ integer=true })),
      rnnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      rnredirect = T.nullable(T.string({ max=512 })),
    },
    -- recentchanges (ApiQueryRecentChanges) -- includes/Api/ApiQueryRecentChanges.php
    recentchanges = {
      rccontinue = T.nullable(T.string({ max=512 })),
      rcdir = T.nullable(T.string({ max=5, enum={ ['newer']=true, ['older']=true } })),
      rcend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      rcexcludeuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
      rcgeneraterevisions = T.nullable(T.string({ max=8 })),
      rclimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      rcnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      rcprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: user, userid, comment, parsedcomment, flags, timestamp, title, ids, sizes, redirect, patrolled, loginfo, tags, sha1
      rcshow = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: minor, !minor, bot, !bot, anon, !anon, redirect, !redirect, patrolled, !patrolled, unpatrolled, autopatrolled, !autopatrolled
      rcslot = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$slotRoles', left generic
      rcstart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      rctag = T.nullable(T.string({ max=512 })),
      rctitle = T.nullable(T.string({ max=512 })),
      rctoponly = T.nullable(T.string({ max=8 })),
      rctype = T.nullable(T.string({ max=2048 })),  -- dynamic enum from 'RecentChange::getChangeTypes()', left generic
      rcuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    },
    -- search (ApiQuerySearch) -- includes/Api/ApiQuerySearch.php
    search = {
      srenablerewrites = T.nullable(T.string({ max=8 })),
      srinfo = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: totalhits, suggestion, rewrittenquery
      srinterwiki = T.nullable(T.string({ max=8 })),
      srlimit = T.nullable(T.number_query({ integer=true })),
      srnamespace = T.nullable(T.string({ max=512 })),  -- mediawiki type: namespace
      sroffset = T.nullable(T.number_query({ integer=true })),
      srprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: size, wordcount, timestamp, snippet, titlesnippet, redirecttitle, redirectsnippet, sectiontitle, sectionsnippet, isfilematch, categorysnippet, score, hasrelated, extensiondata
      srsearch = T.string({ max=512 }),
      srsort = T.nullable(T.string({ max=512 })),  -- dynamic enum from '$this->searchEngineFactory->create()->getValidSorts()', left generic
      srwhat = T.nullable(T.string({ max=9, enum={ ['title']=true, ['text']=true, ['nearmatch']=true } })),
    },
    -- tags (ApiQueryTags) -- includes/Api/ApiQueryTags.php
    tags = {
      tgcontinue = T.nullable(T.string({ max=512 })),
      tglimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      tgprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: displayname, description, hitcount, defined, source, active
    },
    -- trackingcategories (ApiQueryTrackingCategories) -- includes/Api/ApiQueryTrackingCategories.php
    trackingcategories = {
      tccontinue = T.nullable(T.string({ max=512 })),
      tclimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      tcmax = T.nullable(T.number_query({ integer=true })),
      tcmin = T.nullable(T.number_query({ integer=true })),
      tcprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: size, hidden
      tctrackingcatname = T.nullable(T.string({ max=2048 })),
    },
    -- usercontribs (ApiQueryUserContribs) -- includes/Api/ApiQueryUserContribs.php
    usercontribs = {
      uccontinue = T.nullable(T.string({ max=512 })),
      ucdir = T.nullable(T.string({ max=5, enum={ ['newer']=true, ['older']=true } })),
      ucend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      uciprange = T.nullable(T.string({ max=512 })),
      uclimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      ucnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      ucprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, title, timestamp, comment, parsedcomment, size, sizediff, flags, patrolled, tags
      ucshow = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: minor, !minor, patrolled, !patrolled, autopatrolled, !autopatrolled, top, !top, new, !new
      ucstart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      uctag = T.nullable(T.string({ max=512 })),
      uctoponly = T.nullable(T.string({ max=512 })),
      ucuser = T.nullable(T.string({ max=2048 })),  -- mediawiki type: user
      ucuserids = T.nullable(T.number_query({ integer=true })),
      ucuserprefix = T.nullable(T.string({ max=512 })),
    },
    -- users (ApiQueryUsers) -- includes/Api/ApiQueryUsers.php
    users = {
      usattachedwiki = T.nullable(T.string({ max=512 })),
      usprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: blockinfo, groups, groupmemberships, implicitgroups, rights, editcount, registration, emailable, gender, centralids, cancreate, tempexpired
      ususerids = T.nullable(T.number_query({ integer=true })),
      ususers = T.nullable(T.string({ max=2048 })),
    },
    -- watchlist (ApiQueryWatchlist) -- includes/Api/ApiQueryWatchlist.php
    watchlist = {
      wlallrev = T.nullable(T.string({ max=8 })),
      wlcontinue = T.nullable(T.string({ max=512 })),
      wldir = T.nullable(T.string({ max=5, enum={ ['newer']=true, ['older']=true } })),
      wlend = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      wlexcludeuser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
      wllabels = T.nullable(T.number_query({ integer=true })),
      wllimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      wlnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      wlowner = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
      wlprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: ids, title, flags, user, userid, comment, parsedcomment, timestamp, patrol, sizes, notificationtimestamp, loginfo, tags, expiry, labels
      wlshow = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: minor, !minor, bot, !bot, anon, !anon, patrolled, !patrolled, autopatrolled, !autopatrolled, unread, !unread
      wlstart = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
      wltoken = T.nullable(T.string({ max=512 })),
      wltype = T.nullable(T.string({ max=2048 })),  -- dynamic enum from 'RecentChange::getChangeTypes()', left generic
      wluser = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    },
    -- watchlistraw (ApiQueryWatchlistRaw) -- includes/Api/ApiQueryWatchlistRaw.php
    watchlistraw = {
      wrcontinue = T.nullable(T.string({ max=512 })),
      wrdir = T.nullable(T.string({ max=10, enum={ ['ascending']=true, ['descending']=true } })),
      wrfromtitle = T.nullable(T.string({ max=512 })),
      wrlimit = T.nullable(T.number_query({ integer=true, min=1, max=500 })),
      wrnamespace = T.nullable(T.string({ max=2048 })),  -- mediawiki type: namespace
      wrowner = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
      wrprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: changed
      wrshow = T.nullable(T.string({ max=2048 })),
      wrtoken = T.nullable(T.string({ max=512 })),
      wrtotitle = T.nullable(T.string({ max=512 })),
    },
  },
  meta = {
    -- allmessages (ApiQueryAllMessages) -- includes/Api/ApiQueryAllMessages.php
    allmessages = {
      amargs = T.nullable(T.string({ max=2048 })),
      amcustomised = T.nullable(T.string({ max=10, enum={ ['all']=true, ['modified']=true, ['unmodified']=true } })),
      amenableparser = T.nullable(T.string({ max=8 })),
      amfilter = T.nullable(T.string({ max=512 })),
      amfrom = T.nullable(T.string({ max=512 })),
      amincludelocal = T.nullable(T.string({ max=8 })),
      amlang = T.nullable(T.string({ max=512 })),
      ammessages = T.nullable(T.string({ max=2048 })),
      amnocontent = T.nullable(T.string({ max=8 })),
      amprefix = T.nullable(T.string({ max=512 })),
      amprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: default
      amtitle = T.nullable(T.string({ max=512 })),
      amto = T.nullable(T.string({ max=512 })),
    },
    -- authmanagerinfo (ApiQueryAuthManagerInfo) -- includes/Api/ApiQueryAuthManagerInfo.php
    authmanagerinfo = {
      amirequestsfor = T.nullable(T.string({ max=512 })),
      amisecuritysensitiveoperation = T.nullable(T.string({ max=512 })),
    },
    -- filerepoinfo (ApiQueryFileRepoInfo) -- includes/Api/ApiQueryFileRepoInfo.php
    filerepoinfo = {
      friprop = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$props', left generic
    },
    -- languageinfo (ApiQueryLanguageinfo) -- includes/Api/ApiQueryLanguageinfo.php
    languageinfo = {
      licode = T.nullable(T.string({ max=2048 })),
      licontinue = T.nullable(T.string({ max=512 })),
      liprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: code, bcp47, dir, autonym, name, variantnames, fallbacks, variants
    },
    -- siteinfo (ApiQuerySiteinfo) -- includes/Api/ApiQuerySiteinfo.php
    siteinfo = {
      sifilteriw = T.nullable(T.string({ max=6, enum={ ['local']=true, ['!local']=true } })),
      siinlanguagecode = T.nullable(T.string({ max=512 })),
      sinumberingroup = T.nullable(T.string({ max=8 })),
      siprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: general, namespaces, namespacealiases, specialpagealiases, magicwords, interwikimap, dbrepllag, statistics, usergroups, autocreatetempuser, clientlibraries, libraries, extensions, fileextensions, rightsinfo, restrictions, languages, languagevariants, skins, extensiontags, functionhooks, showhooks, variables, doubleunderscores, protocols, defaultoptions, uploaddialog, autopromote, autopromoteonce, copyuploaddomains, sbom
      sishowalldb = T.nullable(T.string({ max=8 })),
    },
    -- tokens (ApiQueryTokens) -- includes/Api/ApiQueryTokens.php
    tokens = {
      ['type'] = T.nullable(T.string({ max=2048 })),  -- dynamic enum from 'array_keys( self::getTokenTypeSalts() )', left generic
    },
    -- userinfo (ApiQueryUserInfo) -- includes/Api/ApiQueryUserInfo.php
    userinfo = {
      uiattachedwiki = T.nullable(T.string({ max=512 })),
      uiprop = T.nullable(T.string({ max=2048 })),  -- pipe-separated list of: blockinfo, hasmsg, groups, groupmemberships, implicitgroups, rights, changeablegroups, options, editcount, ratelimits, theoreticalratelimits, email, realname, acceptlang, registrationdate, unreadcount, watchlistlabels, centralids, latestcontrib, cancreateaccount
    },
  },
}

local function split_pipe_list(s)
  local out = {}
  if type(s) ~= "string" then return out end
  for part in (s .. "|"):gmatch("([^|]*)|") do
    if part ~= "" then out[#out + 1] = part end
  end
  return out
end

-- Unions the field sets of every prop=/list=/meta= submodule named in a
-- query request (each of those args may itself list multiple pipe-separated
-- submodules, e.g. prop=info|revisions).
local function resolve_query_submodule_fields(v)
  local fields = {}
  for _, kind in ipairs({ "prop", "list", "meta" }) do
    for _, name in ipairs(split_pipe_list(v[kind])) do
      local sub = mw_query_submodules[kind] and mw_query_submodules[kind][name]
      if sub then fields = merge(fields, sub) end
    end
  end
  -- generator=X reuses submodule X's own params (X must be prop= or list=
  -- eligible, i.e. extend ApiQueryGeneratorBase - ~24 core submodules do:
  -- categorymembers, search, prefixsearch, images, links, ... ), but every
  -- wire name gets an extra leading 'g' (list=prefixsearch's pssearch becomes
  -- generator=prefixsearch's gpssearch). Fixed, uniform ApiPageSet convention,
  -- not something each submodule declares in its own getAllowedParams().
  if v.generator then
    local gen_sub = (mw_query_submodules.list and mw_query_submodules.list[v.generator])
                 or (mw_query_submodules.prop and mw_query_submodules.prop[v.generator])
    if gen_sub then
      for key, validator in pairs(gen_sub) do
        fields["g" .. key] = validator
      end
    end
  end
  return fields
end

local mw_api_action_fields_union = {}
for _, fields in pairs(mw_api_actions) do
  mw_api_action_fields_union = merge(mw_api_action_fields_union, fields)
end
local mw_query_submodule_fields_union = {}
for _, kind_fields in pairs(mw_query_submodules) do
  for _, fields in pairs(kind_fields) do
    mw_query_submodule_fields_union = merge(mw_query_submodule_fields_union, fields)
  end
end
-- T.with_check validates the base object schema (this union) BEFORE
-- api_check ever runs, so generator=X's g-prefixed field names (see
-- resolve_query_submodule_fields() below) need to be allowed here too,
-- not just in the per-request dynamic lookup - otherwise the base schema
-- rejects them before api_check's own generator= narrowing gets a chance.
for _, kind in ipairs({ "prop", "list" }) do
  for _, fields in pairs(mw_query_submodules[kind] or {}) do
    for key, validator in pairs(fields) do
      mw_query_submodule_fields_union["g" .. key] = validator
    end
  end
end

























-- list=allusers is a user-enumeration lookup (used by admin pages like
-- Special:ListUsers / Special:ActiveUsers / Special:RenameUser to populate
-- autocomplete). As a lightweight defense against direct, unauthenticated
-- scripting of that lookup, it additionally requires a same-origin Referer
-- from one of the admin pages that legitimately trigger it. This is a soft
-- check only — Referer is client-supplied and can be forged by anyone who
-- can also forge query params — real authorization is still MediaWiki's job.
local ALLUSERS_REFERER_PAGES = {
  "Special:Log", "Special:NewPages", "Special:Block", "Special:ListUsers",
  "Special:UserRights", "Special:BlockList", "Special:ActiveUsers",
  "Special:Contributions", "Special:RenameUser",
}

local function referer_allows_allusers()
  local referer = ngx.req.get_headers()["referer"]
  if type(referer) == "table" then referer = referer[1] end
  if type(referer) ~= "string" then return false end

  local ref_host, ref_path = referer:match("^https?://([^/]+)(/.*)$")
  local host = ngx.req.get_headers()["host"]
  if type(host) == "table" then host = host[1] end
  if not ref_host or ref_host ~= host then return false end

  -- Case-insensitive for the same reason as title_is() above: MediaWiki
  -- case-folds special page names, so the Referer could spell the page
  -- name differently than our hardcoded ALLUSERS_REFERER_PAGES strings.
  local ref_path_lower = ref_path:lower()
  for _, page in ipairs(ALLUSERS_REFERER_PAGES) do
    local page_lower = page:lower()
    if ref_path_lower:find("/index.php/" .. page_lower, 1, true) == 1 then return true end
    if ref_path_lower:find("/index.php", 1, true) == 1 and
       (ref_path_lower:find("title=" .. page_lower, 1, true) or
        ref_path_lower:find("title=" .. page_lower:gsub(":", "%%3a"), 1, true))
    then
      return true
    end
  end
  return false
end

local function api_check(v, path)
  if v.list == "allusers" and not referer_allows_allusers() then
    return false, path .. ": list=allusers requires a same-origin Referer from an authorized admin page"
  end

  local action_fields = v.action and mw_api_actions[v.action]
  if action_fields then
    local extra_fields = action_fields
    if v.action == "query" then
      extra_fields = merge(action_fields, resolve_query_submodule_fields(v))
    end
    for key in pairs(v) do
      -- api_legacy_fields stays globally allowed even for precisely-modeled
      -- actions: it includes MediaWiki's shared page-set resolution fields
      -- (titles, pageids, generator, redirects, ...) used across many
      -- action=query submodules, which aren't part of any one submodule's
      -- own getAllowedParams() and so aren't captured per-action above.
      if api_common[key] == nil and api_legacy_fields[key] == nil and extra_fields[key] == nil then
        return false, path .. "." .. key .. ": not a valid parameter for action=" .. v.action
      end
    end
  end

  return true
end

-- Shared by both the GET (query string) and POST (form body) routes below -
-- api.php's parameter namespace is the same regardless of HTTP method.
local api_schema = T.with_check(
  T.object(merge(api_common, api_legacy_fields, mw_api_action_fields_union, mw_query_submodule_fields_union)),
  api_check
)

-- ---------------------------------------------------------------------------
-- index.php POST form schema - the standard wikitext edit-submission form
-- (EditPage.php). Generated from editpage-fields.json (extract_mediawiki_api.py,
-- heuristic $request->getXxx() scan - candidate field NAMES only, no type info,
-- so most fields are generously-capped nullable strings; a handful of known
-- checkbox/enum fields get a tighter FIELD_OVERRIDES entry in gen_editpage_form.py.
-- None are marked required since MediaWiki's own form-building logic determines
-- which fields are present per action (preview/save/diff).
-- ---------------------------------------------------------------------------
local index_post_form = T.object({
  bot = T.nullable(T.string({ max=8 })),
  editRevId = T.nullable(T.string({ max=512 })),
  editintro = T.nullable(T.string({ max=512 })),
  format = T.nullable(T.string({ max=512 })),
  minor = T.nullable(T.string({ max=8 })),
  mode = T.nullable(T.string({ max=512 })),
  model = T.nullable(T.string({ max=512 })),
  nosummary = T.nullable(T.string({ max=8 })),
  oldid = T.nullable(T.string({ max=512 })),
  parentRevId = T.nullable(T.string({ max=512 })),
  preload = T.nullable(T.string({ max=512 })),
  preloadparams = T.nullable(T.string({ max=2048 })),
  preloadtitle = T.nullable(T.string({ max=512 })),
  preview = T.nullable(T.string({ max=8 })),
  redlink = T.nullable(T.string({ max=8 })),
  section = T.nullable(T.string({ max=512 })),
  summary = T.nullable(T.string({ max=2048 })),
  undo = T.nullable(T.string({ max=512 })),
  undoafter = T.nullable(T.string({ max=512 })),
  watchthis = T.nullable(T.string({ max=8 })),
  wpAllowedProblematicRedirectTarget = T.nullable(T.string({ max=8 })),
  wpAntispam = T.nullable(T.string({ max=64 })),
  wpAutoSummary = T.nullable(T.string({ max=2048 })),
  wpChangeTags = T.nullable(T.string({ max=2048 })),
  wpChangeTagsAfterPreview = T.nullable(T.string({ max=8 })),
  wpDiff = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpEdittime = T.nullable(T.string({ max=512 })),
  wpExtraQueryRedirect = T.nullable(T.string({ max=512 })),
  wpIgnoreBlankArticle = T.nullable(T.string({ max=8 })),
  wpIgnoreBlankSummary = T.nullable(T.string({ max=8 })),
  wpIgnoreProblematicRedirects = T.nullable(T.string({ max=8 })),
  wpIgnoreRevisionDeleted = T.nullable(T.string({ max=8 })),
  wpMinoredit = T.nullable(T.string({ max=8 })),
  wpPreview = T.nullable(T.string({ max=8 })),
  wpRecreate = T.nullable(T.string({ max=8 })),
  wpSave = T.nullable(T.string({ max=512 })),
  wpScrolltop = T.nullable(T.string({ max=512 })),
  wpSection = T.nullable(T.string({ max=512 })),
  wpSectionTitle = T.nullable(T.string({ max=512 })),
  wpStarttime = T.nullable(T.string({ max=512 })),
  wpSummary = T.nullable(T.string({ max=2048 })),
  wpTextbox1 = T.nullable(T.string({ max=1048576 })),
  wpTextbox2 = T.nullable(T.string({ max=1048576 })),
  wpUltimateParam = T.nullable(T.string({ max=4, enum={ ['1']=true } })),
  wpUndidRevision = T.nullable(T.string({ max=512 })),
  wpUndoAfter = T.nullable(T.string({ max=512 })),
  wpUnicodeCheck = T.nullable(T.string({ max=64 })),
  wpWatchlistExpiry = T.nullable(T.string({ max=512 })),
  wpWatchlistLabels = T.nullable(T.string({ max=2048 })),
  wpWatchthis = T.nullable(T.string({ max=8 })),
})

-- ---------------------------------------------------------------------------
-- index.php action=X POST forms (includes/Actions/*.php + Page/ProtectionForm.php).
-- Generated from index-actions.json (extract_mediawiki_api.py). Candidate field
-- NAMES only (getFormFields() types where available, else a heuristic scan), so
-- fields are generously-capped nullable strings - same convention as the Special:
-- page routes. title/wpEditToken/wpFormIdentifier are added to every form: they're
-- injected unconditionally by HTMLForm::getHiddenFields() for any POST-method form,
-- not read back by the action's own code, so no scan of it ever finds them.
-- Which action= a POST is for lives in the query string (index_query already
-- allows it), not the body, so all of these are added to 'index php post' via
-- form_schemas - core.lua tries each in turn and passes if any one matches.
-- ---------------------------------------------------------------------------
-- DeleteAction (action='delete', method=form_fields) -- includes/Actions/DeleteAction.php
local action_deleteaction_form = T.object({
  title = T.nullable(T.string({ max=512 })),
  wpConfirmB = T.nullable(T.string({ max=512 })),
  wpConfirmationRevId = T.nullable(T.string({ max=512 })),
  wpDeleteReasonList = T.nullable(T.string({ max=1024 })),
  wpDeleteTalk = T.nullable(T.string({ max=8 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFormIdentifier = T.nullable(T.string({ max=512 })),
  wpReason = T.nullable(T.string({ max=1024 })),
  wpSuppress = T.nullable(T.string({ max=8 })),
  wpWatch = T.nullable(T.string({ max=8 })),
  wpWatchlistExpiry = T.nullable(T.string({ max=512 })),
})

-- MarkpatrolledAction (action='markpatrolled', method=heuristic) -- includes/Actions/MarkpatrolledAction.php
local action_markpatrolledaction_form = T.object({
  rcid = T.nullable(T.string({ max=512 })),
  title = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFormIdentifier = T.nullable(T.string({ max=512 })),
})

-- McrRestoreAction (action='mcrrestore', method=form_fields) -- includes/Actions/McrUndoAction.php
local action_mcrrestoreaction_form = T.object({
  title = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFormIdentifier = T.nullable(T.string({ max=512 })),
  wpSummary = T.nullable(T.string({ max=2048 })),
  wpdiff = T.nullable(T.string({ max=512 })),
  wpsummarypreview = T.nullable(T.string({ max=2048 })),
})

-- McrUndoAction (action='mcrundo', method=form_fields) -- includes/Actions/McrUndoAction.php
local action_mcrundoaction_form = T.object({
  title = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFormIdentifier = T.nullable(T.string({ max=512 })),
  wpSummary = T.nullable(T.string({ max=2048 })),
  wpdiff = T.nullable(T.string({ max=512 })),
  wpsummarypreview = T.nullable(T.string({ max=2048 })),
})

-- ProtectAction (action='protect', method=heuristic) -- includes/Page/ProtectionForm.php
local action_protectaction_form = T.object({
  ['mwProtect-cascade'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-expiry-create'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-expiry-edit'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-expiry-move'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-expiry-upload'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-level-create'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-level-edit'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-level-move'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-level-upload'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-reason'] = T.nullable(T.string({ max=1024 })),
  mwProtectWatch = T.nullable(T.string({ max=512 })),
  title = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFormIdentifier = T.nullable(T.string({ max=512 })),
  ['wpProtectExpirySelection-create'] = T.nullable(T.string({ max=512 })),
  ['wpProtectExpirySelection-edit'] = T.nullable(T.string({ max=512 })),
  ['wpProtectExpirySelection-move'] = T.nullable(T.string({ max=512 })),
  ['wpProtectExpirySelection-upload'] = T.nullable(T.string({ max=512 })),
  wpProtectReasonSelection = T.nullable(T.string({ max=1024 })),
})

-- PurgeAction (action='purge', method=form_fields) -- includes/Actions/PurgeAction.php
local action_purgeaction_form = T.object({
  title = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFormIdentifier = T.nullable(T.string({ max=512 })),
  wpintro = T.nullable(T.string({ max=512 })),
})

-- RevertAction (action='revert', method=form_fields) -- includes/Actions/RevertAction.php
local action_revertaction_form = T.object({
  title = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFormIdentifier = T.nullable(T.string({ max=512 })),
  wpcomment = T.nullable(T.string({ max=1024 })),
  wpintro = T.nullable(T.string({ max=512 })),
})

-- RollbackAction (action='rollback', method=form_fields) -- includes/Actions/RollbackAction.php
local action_rollbackaction_form = T.object({
  title = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFormIdentifier = T.nullable(T.string({ max=512 })),
  wpintro = T.nullable(T.string({ max=512 })),
})

-- UnprotectAction (action='unprotect', method=heuristic) -- includes/Page/ProtectionForm.php
local action_unprotectaction_form = T.object({
  ['mwProtect-cascade'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-expiry-create'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-expiry-edit'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-expiry-move'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-expiry-upload'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-level-create'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-level-edit'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-level-move'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-level-upload'] = T.nullable(T.string({ max=512 })),
  ['mwProtect-reason'] = T.nullable(T.string({ max=1024 })),
  mwProtectWatch = T.nullable(T.string({ max=512 })),
  title = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFormIdentifier = T.nullable(T.string({ max=512 })),
  ['wpProtectExpirySelection-create'] = T.nullable(T.string({ max=512 })),
  ['wpProtectExpirySelection-edit'] = T.nullable(T.string({ max=512 })),
  ['wpProtectExpirySelection-move'] = T.nullable(T.string({ max=512 })),
  ['wpProtectExpirySelection-upload'] = T.nullable(T.string({ max=512 })),
  wpProtectReasonSelection = T.nullable(T.string({ max=1024 })),
})

-- UnwatchAction (action='unwatch', method=form_fields) -- includes/Actions/UnwatchAction.php
local action_unwatchaction_form = T.object({
  title = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFormIdentifier = T.nullable(T.string({ max=512 })),
  wpintro = T.nullable(T.string({ max=512 })),
})

-- WatchAction (action='watch', method=form_fields) -- includes/Actions/WatchAction.php
local action_watchaction_form = T.object({
  title = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFormIdentifier = T.nullable(T.string({ max=512 })),
  wplabels = T.nullable(T.string({ max=512 })),
})

local mw_index_action_forms = {
  action_deleteaction_form,
  action_markpatrolledaction_form,
  action_mcrrestoreaction_form,
  action_mcrundoaction_form,
  action_protectaction_form,
  action_purgeaction_form,
  action_revertaction_form,
  action_rollbackaction_form,
  action_unprotectaction_form,
  action_unwatchaction_form,
  action_watchaction_form,
}

-- ==========================================================================
-- Dedicated routes for every core Special: page (Tier 6, full coverage).
-- Generated from special-fields.json (extract_mediawiki_api.py). Field data
-- comes from, in priority order: FormSpecialPage::getFormFields() (precise
-- types), a redirect stub's constructor pass-through list, or a heuristic
-- $request->getXxx() scan (generic strings). QueryPage-family report pages
-- and pages where nothing was found get no page-specific extra fields at
-- all - just the common index.php baseline (idx_common). One array local,
-- not one named local per route/form (Lua caps a chunk at 200 locals).
-- ==========================================================================
local mw_bulk_special_routes = {
  -- Activeusers (SpecialActiveUsers, extends=SpecialPage, method=heuristic) -- Specials/SpecialActiveUsers.php
  {
    name    = "index php special activeusers post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Activeusers(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      hidebots = T.nullable(T.string({ max=512 })),
      hidesysops = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- AllMyUploads (SpecialAllMyUploads, extends=RedirectSpecialPage, method=redirect_passthrough) -- Specials/Redirects/SpecialAllMyUploads.php
  {
    name    = "index php special allmyuploads",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:AllMyUploads(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Allmessages (SpecialAllMessages, extends=SpecialPage, method=none) -- Specials/SpecialAllMessages.php
  -- Allpages (SpecialAllPages, extends=IncludableSpecialPage, method=heuristic) -- Specials/SpecialAllPages.php
  {
    name    = "index php special allpages post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Allpages(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      from = T.nullable(T.string({ max=512 })),
      hideredirects = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      to = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Ancientpages (SpecialAncientPages, extends=QueryPage, method=query_page_standard) -- Specials/SpecialAncientPages.php
  {
    name    = "index php special ancientpages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Ancientpages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- ApiHelp (SpecialApiHelp, extends=UnlistedSpecialPage, method=heuristic) -- Specials/SpecialApiHelp.php
  {
    name    = "index php special apihelp",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:ApiHelp(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      recursivesubmodules = T.nullable(T.string({ max=512 })),
      submodules = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special apihelp post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:ApiHelp(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      recursivesubmodules = T.nullable(T.string({ max=512 })),
      submodules = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- ApiSandbox (SpecialApiSandbox, extends=SpecialPage, method=none) -- Specials/SpecialApiSandbox.php
  {
    name    = "index php special apisandbox",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:ApiSandbox(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- AuthenticationPopupSuccess (SpecialAuthenticationPopupSuccess, extends=UnlistedSpecialPage, method=heuristic) -- Specials/SpecialAuthenticationPopupSuccess.php
  {
    name    = "index php special authenticationpopupsuccess",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:AuthenticationPopupSuccess(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      display = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special authenticationpopupsuccess post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:AuthenticationPopupSuccess(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      display = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- AutoblockList (SpecialAutoblockList, extends=SpecialPage, method=none) -- Specials/SpecialAutoblockList.php
  {
    name    = "index php special autoblocklist",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:AutoblockList(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Blankpage (SpecialBlankpage, extends=UnlistedSpecialPage, method=none) -- Specials/SpecialBlankpage.php
  {
    name    = "index php special blankpage",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Blankpage(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Block (SpecialBlock, extends=FormSpecialPage, method=form_fields) -- Specials/SpecialBlock.php
  {
    name    = "index php special block",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Block(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  {
    name    = "index php special block post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Block(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpActionRestrictions = T.nullable(T.string({ max=512 })),
      wpAutoBlock = T.nullable(T.string({ max=8 })),
      wpConfirm = T.nullable(T.string({ max=512 })),
      wpCreateAccount = T.nullable(T.string({ max=8 })),
      wpDisableEmail = T.nullable(T.string({ max=8 })),
      wpDisableUTEdit = T.nullable(T.string({ max=8 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpEditingRestriction = T.nullable(T.string({ max=512 })),
      wpExpiry = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpHardBlock = T.nullable(T.string({ max=8 })),
      wpHideUser = T.nullable(T.string({ max=8 })),
      wpNamespaceRestrictions = T.nullable(T.string({ max=512 })),
      wpPageRestrictions = T.nullable(T.string({ max=512 })),
      wpPreviousTarget = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpTarget = T.nullable(T.string({ max=512 })),
      wpWatch = T.nullable(T.string({ max=8 })),
    }),
  },
  -- BlockList (SpecialBlockList, extends=SpecialPage, method=heuristic) -- Specials/SpecialBlockList.php
  {
    name    = "index php special blocklist",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:BlockList(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      action = T.nullable(T.string({ max=512 })),
      blockType = T.nullable(T.string({ max=512 })),
      ip = T.nullable(T.string({ max=512 })),
      wpOptions = T.nullable(T.string({ max=512 })),
      wpTarget = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special blocklist post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:BlockList(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      blockType = T.nullable(T.string({ max=512 })),
      ip = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpOptions = T.nullable(T.string({ max=512 })),
      wpTarget = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Booksources (SpecialBookSources, extends=SpecialPage, method=heuristic) -- Specials/SpecialBookSources.php
  {
    name    = "index php special booksources",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Booksources(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      isbn = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special booksources post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Booksources(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      isbn = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- BotPasswords (SpecialBotPasswords, extends=FormSpecialPage, method=form_fields) -- Specials/SpecialBotPasswords.php
  {
    name    = "index php special botpasswords",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:BotPasswords(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  {
    name    = "index php special botpasswords post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:BotPasswords(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpappId = T.nullable(T.string({ max=512 })),
      wpgrants = T.nullable(T.string({ max=512 })),
      wpresetPassword = T.nullable(T.string({ max=8 })),
      wprestrictions = T.nullable(T.string({ max=512 })),
    }),
  },
  -- BrokenRedirects (SpecialBrokenRedirects, extends=QueryPage, method=query_page_standard) -- Specials/SpecialBrokenRedirects.php
  {
    name    = "index php special brokenredirects",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:BrokenRedirects(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Categories (SpecialCategories, extends=SpecialPage, method=heuristic) -- Specials/SpecialCategories.php
  {
    name    = "index php special categories",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Categories(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      from = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special categories post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Categories(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      from = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- ChangeContentModel (SpecialChangeContentModel, extends=FormSpecialPage, method=form_fields) -- Specials/SpecialChangeContentModel.php
  {
    name    = "index php special changecontentmodel",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:ChangeContentModel(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  {
    name    = "index php special changecontentmodel post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:ChangeContentModel(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      model = T.nullable(T.string({ max=512 })),
      pagetitle = T.nullable(T.string({ max=512 })),
      reason = T.nullable(T.string({ max=1024 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- ChangeCredentials (SpecialChangeCredentials, extends=AuthManagerSpecialPage, method=heuristic) -- Specials/SpecialChangeCredentials.php
  {
    name    = "index php special changecredentials",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:ChangeCredentials(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      password = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      retype = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
      wpusername = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special changecredentials post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:ChangeCredentials(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      password = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      retype = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpusername = T.nullable(T.string({ max=512 })),
    }),
  },
  -- ChangePassword (SpecialChangePassword, extends=SpecialRedirectToSpecial, method=redirect_passthrough) -- Specials/SpecialChangePassword.php
  {
    name    = "index php special changepassword",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:ChangePassword(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      returnto = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  -- ComparePages (SpecialComparePages, extends=SpecialPage, method=none) -- Specials/SpecialComparePages.php
  -- Contribute (SpecialContribute, extends=IncludableSpecialPage, method=none) -- Specials/SpecialContribute.php
  {
    name    = "index php special contribute",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Contribute(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Contributions (SpecialContributions, extends=ContributionsSpecialPage, method=heuristic) -- Specials/SpecialContributions.php
  {
    name    = "index php special contributions post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Contributions(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      associated = T.nullable(T.string({ max=512 })),
      bot = T.nullable(T.string({ max=512 })),
      deletedOnly = T.nullable(T.string({ max=512 })),
      ['end'] = T.nullable(T.string({ max=512 })),
      feed = T.nullable(T.string({ max=512 })),
      hideMinor = T.nullable(T.string({ max=512 })),
      limit = T.nullable(T.string({ max=512 })),
      month = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      newOnly = T.nullable(T.string({ max=512 })),
      nsInvert = T.nullable(T.string({ max=512 })),
      start = T.nullable(T.string({ max=512 })),
      tagInvert = T.nullable(T.string({ max=512 })),
      tagfilter = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      topOnly = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpfilters = T.nullable(T.string({ max=512 })),
      year = T.nullable(T.string({ max=512 })),
    }),
  },
  -- CreateAccount (SpecialCreateAccount, extends=LoginSignupSpecialPage, method=heuristic) -- Specials/SpecialCreateAccount.php
  {
    name    = "index php special createaccount",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:CreateAccount(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      action = T.nullable(T.string({ max=512 })),
      alwaysShowLogin = T.nullable(T.string({ max=512 })),
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      error = T.nullable(T.string({ max=512 })),
      force = T.nullable(T.string({ max=512 })),
      fromhttp = T.nullable(T.string({ max=512 })),
      notice = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      warning = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
      wpCreateaccount = T.nullable(T.string({ max=512 })),
      wpCreateaccountMail = T.nullable(T.string({ max=512 })),
      wpCreateaccountToken = T.nullable(T.string({ max=512 })),
      wpEmail = T.nullable(T.string({ max=512 })),
      wpForceHttps = T.nullable(T.string({ max=512 })),
      wpFromhttp = T.nullable(T.string({ max=512 })),
      wpLoginToken = T.nullable(T.string({ max=512 })),
      wpName = T.nullable(T.string({ max=512 })),
      wpName1 = T.nullable(T.string({ max=512 })),
      wpName2 = T.nullable(T.string({ max=512 })),
      wpPassword = T.nullable(T.string({ max=512 })),
      wpPassword1 = T.nullable(T.string({ max=512 })),
      wpPassword2 = T.nullable(T.string({ max=512 })),
      wpRealName = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpRemember = T.nullable(T.string({ max=512 })),
      wpRetype = T.nullable(T.string({ max=512 })),
      wploginattempt = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special createaccount post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:CreateAccount(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      alwaysShowLogin = T.nullable(T.string({ max=512 })),
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      error = T.nullable(T.string({ max=512 })),
      force = T.nullable(T.string({ max=512 })),
      fromhttp = T.nullable(T.string({ max=512 })),
      notice = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      warning = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
      wpCreateaccount = T.nullable(T.string({ max=512 })),
      wpCreateaccountMail = T.nullable(T.string({ max=512 })),
      wpCreateaccountToken = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpEmail = T.nullable(T.string({ max=512 })),
      wpForceHttps = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpFromhttp = T.nullable(T.string({ max=512 })),
      wpLoginToken = T.nullable(T.string({ max=512 })),
      wpName = T.nullable(T.string({ max=512 })),
      wpName1 = T.nullable(T.string({ max=512 })),
      wpName2 = T.nullable(T.string({ max=512 })),
      wpPassword = T.nullable(T.string({ max=512 })),
      wpPassword1 = T.nullable(T.string({ max=512 })),
      wpPassword2 = T.nullable(T.string({ max=512 })),
      wpRealName = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpRemember = T.nullable(T.string({ max=512 })),
      wpRetype = T.nullable(T.string({ max=512 })),
      wploginattempt = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Deadendpages (SpecialDeadendPages, extends=PageQueryPage, method=query_page_standard) -- Specials/SpecialDeadendPages.php
  {
    name    = "index php special deadendpages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Deadendpages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- DeletePage (SpecialDeletePage, extends=SpecialRedirectWithAction, method=redirect_passthrough) -- Specials/SpecialDeletePage.php
  {
    name    = "index php special deletepage",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:DeletePage(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- DeletedContributions (SpecialDeletedContributions, extends=ContributionsSpecialPage, method=heuristic) -- Specials/SpecialDeletedContributions.php
  {
    name    = "index php special deletedcontributions",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:DeletedContributions(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      associated = T.nullable(T.string({ max=512 })),
      bot = T.nullable(T.string({ max=512 })),
      deletedOnly = T.nullable(T.string({ max=512 })),
      ['end'] = T.nullable(T.string({ max=512 })),
      feed = T.nullable(T.string({ max=512 })),
      hideMinor = T.nullable(T.string({ max=512 })),
      limit = T.nullable(T.string({ max=512 })),
      month = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      newOnly = T.nullable(T.string({ max=512 })),
      nsInvert = T.nullable(T.string({ max=512 })),
      start = T.nullable(T.string({ max=512 })),
      tagInvert = T.nullable(T.string({ max=512 })),
      tagfilter = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      topOnly = T.nullable(T.string({ max=512 })),
      wpfilters = T.nullable(T.string({ max=512 })),
      year = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special deletedcontributions post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:DeletedContributions(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      associated = T.nullable(T.string({ max=512 })),
      bot = T.nullable(T.string({ max=512 })),
      deletedOnly = T.nullable(T.string({ max=512 })),
      ['end'] = T.nullable(T.string({ max=512 })),
      feed = T.nullable(T.string({ max=512 })),
      hideMinor = T.nullable(T.string({ max=512 })),
      limit = T.nullable(T.string({ max=512 })),
      month = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      newOnly = T.nullable(T.string({ max=512 })),
      nsInvert = T.nullable(T.string({ max=512 })),
      start = T.nullable(T.string({ max=512 })),
      tagInvert = T.nullable(T.string({ max=512 })),
      tagfilter = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      topOnly = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpfilters = T.nullable(T.string({ max=512 })),
      year = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Diff (SpecialDiff, extends=RedirectSpecialPage, method=redirect_passthrough) -- Specials/SpecialDiff.php
  {
    name    = "index php special diff",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Diff(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- DoubleRedirects (SpecialDoubleRedirects, extends=QueryPage, method=query_page_standard) -- Specials/SpecialDoubleRedirects.php
  {
    name    = "index php special doubleredirects",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:DoubleRedirects(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- EditPage (SpecialEditPage, extends=SpecialRedirectWithAction, method=redirect_passthrough) -- Specials/SpecialEditPage.php
  {
    name    = "index php special editpage",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:EditPage(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- EditTags (SpecialEditTags, extends=UnlistedSpecialPage, method=heuristic) -- Specials/SpecialEditTags.php
  {
    name    = "index php special edittags",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:EditTags(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      ids = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      type = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpExistingTags = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpRemoveAllTags = T.nullable(T.string({ max=512 })),
      wpSubmit = T.nullable(T.string({ max=512 })),
      wpTagList = T.nullable(T.string({ max=512 })),
      wpTagsToRemove = T.nullable(T.string({ max=512 })),
      wpfilters = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special edittags post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:EditTags(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      ids = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      type = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpExistingTags = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpRemoveAllTags = T.nullable(T.string({ max=512 })),
      wpSubmit = T.nullable(T.string({ max=512 })),
      wpTagList = T.nullable(T.string({ max=512 })),
      wpTagsToRemove = T.nullable(T.string({ max=512 })),
      wpfilters = T.nullable(T.string({ max=512 })),
    }),
  },
  -- EditWatchlist (SpecialEditWatchlist, extends=UnlistedSpecialPage, method=heuristic) -- Specials/SpecialEditWatchlist.php
  {
    name    = "index php special editwatchlist",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:EditWatchlist(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      action = T.nullable(T.string({ max=512 })),
      limit = T.nullable(T.string({ max=512 })),
      watchlistlabels = T.nullable(T.string({ max=512 })),
      ['watchlistlabels-action'] = T.nullable(T.string({ max=512 })),
      wpTitles = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special editwatchlist post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:EditWatchlist(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      limit = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      watchlistlabels = T.nullable(T.string({ max=512 })),
      ['watchlistlabels-action'] = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpTitles = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Emailuser (SpecialEmailUser, extends=SpecialPage, method=form_fields) -- Specials/SpecialEmailUser.php
  {
    name    = "index php special emailuser",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Emailuser(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  {
    name    = "index php special emailuser post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Emailuser(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpCCMe = T.nullable(T.string({ max=8 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpFrom = T.nullable(T.string({ max=512 })),
      wpSubject = T.nullable(T.string({ max=512 })),
      wpTarget = T.nullable(T.string({ max=512 })),
      wpText = T.nullable(T.string({ max=1048576 })),
      wpTo = T.nullable(T.string({ max=512 })),
    }),
  },
  -- ExpandTemplates (SpecialExpandTemplates, extends=SpecialPage, method=heuristic) -- Specials/SpecialExpandTemplates.php
  {
    name    = "index php special expandtemplates",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:ExpandTemplates(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      wpContextTitle = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpGenerateRawHtml = T.nullable(T.string({ max=512 })),
      wpGenerateXml = T.nullable(T.string({ max=512 })),
      wpInput = T.nullable(T.string({ max=512 })),
      wpRemoveComments = T.nullable(T.string({ max=512 })),
      wpRemoveNowiki = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special expandtemplates post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:ExpandTemplates(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpContextTitle = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpGenerateRawHtml = T.nullable(T.string({ max=512 })),
      wpGenerateXml = T.nullable(T.string({ max=512 })),
      wpInput = T.nullable(T.string({ max=512 })),
      wpRemoveComments = T.nullable(T.string({ max=512 })),
      wpRemoveNowiki = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Export (SpecialExport, extends=SpecialPage, method=heuristic) -- Specials/SpecialExport.php
  {
    name    = "index php special export",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Export(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      addcat = T.nullable(T.string({ max=512 })),
      addns = T.nullable(T.string({ max=512 })),
      catname = T.nullable(T.string({ max=512 })),
      curonly = T.nullable(T.string({ max=512 })),
      dir = T.nullable(T.string({ max=512 })),
      exportall = T.nullable(T.string({ max=512 })),
      history = T.nullable(T.string({ max=512 })),
      limit = T.nullable(T.string({ max=512 })),
      listauthors = T.nullable(T.string({ max=512 })),
      nsindex = T.nullable(T.string({ max=512 })),
      offset = T.nullable(T.string({ max=512 })),
      ['pagelink-depth'] = T.nullable(T.string({ max=512 })),
      pages = T.nullable(T.string({ max=512 })),
      templates = T.nullable(T.string({ max=512 })),
      wpDownload = T.nullable(T.string({ max=512 })),
      wpExportTemplates = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special export post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Export(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      addcat = T.nullable(T.string({ max=512 })),
      addns = T.nullable(T.string({ max=512 })),
      catname = T.nullable(T.string({ max=512 })),
      curonly = T.nullable(T.string({ max=512 })),
      dir = T.nullable(T.string({ max=512 })),
      exportall = T.nullable(T.string({ max=512 })),
      history = T.nullable(T.string({ max=512 })),
      limit = T.nullable(T.string({ max=512 })),
      listauthors = T.nullable(T.string({ max=512 })),
      nsindex = T.nullable(T.string({ max=512 })),
      offset = T.nullable(T.string({ max=512 })),
      ['pagelink-depth'] = T.nullable(T.string({ max=512 })),
      pages = T.nullable(T.string({ max=512 })),
      templates = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpDownload = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpExportTemplates = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Fewestrevisions (SpecialFewestRevisions, extends=QueryPage, method=query_page_standard) -- Specials/SpecialFewestRevisions.php
  {
    name    = "index php special fewestrevisions",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Fewestrevisions(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- FileDuplicateSearch (SpecialFileDuplicateSearch, extends=SpecialPage, method=heuristic) -- Specials/SpecialFileDuplicateSearch.php
  {
    name    = "index php special fileduplicatesearch",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:FileDuplicateSearch(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      filename = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special fileduplicatesearch post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:FileDuplicateSearch(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      filename = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Filepath (SpecialFilepath, extends=RedirectSpecialPage, method=redirect_passthrough) -- Specials/SpecialFilepath.php
  {
    name    = "index php special filepath",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Filepath(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- GoToInterwiki (SpecialGoToInterwiki, extends=UnlistedSpecialPage, method=none) -- Specials/SpecialGoToInterwiki.php
  {
    name    = "index php special gotointerwiki",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:GoToInterwiki(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Import (SpecialImport, extends=SpecialPage, method=heuristic) -- Specials/SpecialImport.php
  {
    name    = "index php special import",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Import(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      action = T.nullable(T.string({ max=512 })),
      assignKnownUsers = T.nullable(T.string({ max=512 })),
      frompage = T.nullable(T.string({ max=512 })),
      interwiki = T.nullable(T.string({ max=512 })),
      interwikiHistory = T.nullable(T.string({ max=512 })),
      interwikiTemplates = T.nullable(T.string({ max=512 })),
      ['log-comment'] = T.nullable(T.string({ max=1024 })),
      mapping = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      ['pagelink-depth'] = T.nullable(T.string({ max=512 })),
      rootpage = T.nullable(T.string({ max=512 })),
      source = T.nullable(T.string({ max=512 })),
      subproject = T.nullable(T.string({ max=512 })),
      usernamePrefix = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special import post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Import(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      assignKnownUsers = T.nullable(T.string({ max=512 })),
      frompage = T.nullable(T.string({ max=512 })),
      interwiki = T.nullable(T.string({ max=512 })),
      interwikiHistory = T.nullable(T.string({ max=512 })),
      interwikiTemplates = T.nullable(T.string({ max=512 })),
      ['log-comment'] = T.nullable(T.string({ max=1024 })),
      mapping = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      ['pagelink-depth'] = T.nullable(T.string({ max=512 })),
      rootpage = T.nullable(T.string({ max=512 })),
      source = T.nullable(T.string({ max=512 })),
      subproject = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      usernamePrefix = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Interwiki (SpecialInterwiki, extends=SpecialPage, method=heuristic) -- Specials/SpecialInterwiki.php
  {
    name    = "index php special interwiki",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Interwiki(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      action = T.nullable(T.string({ max=512 })),
      prefix = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special interwiki post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Interwiki(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      prefix = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- LinkAccounts (SpecialLinkAccounts, extends=AuthManagerSpecialPage, method=heuristic) -- Specials/SpecialLinkAccounts.php
  {
    name    = "index php special linkaccounts",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:LinkAccounts(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special linkaccounts post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:LinkAccounts(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- LinkSearch (SpecialLinkSearch, extends=QueryPage, method=query_page_standard) -- Specials/SpecialLinkSearch.php
  -- ListDuplicatedFiles (SpecialListDuplicatedFiles, extends=QueryPage, method=query_page_standard) -- Specials/SpecialListDuplicatedFiles.php
  {
    name    = "index php special listduplicatedfiles",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:ListDuplicatedFiles(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Listadmins (SpecialListAdmins, extends=SpecialRedirectToSpecial, method=redirect_passthrough) -- Specials/Redirects/SpecialListAdmins.php
  {
    name    = "index php special listadmins",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Listadmins(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Listbots (SpecialListBots, extends=SpecialRedirectToSpecial, method=redirect_passthrough) -- Specials/Redirects/SpecialListBots.php
  {
    name    = "index php special listbots",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Listbots(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Listfiles (SpecialListFiles, extends=IncludableSpecialPage, method=heuristic) -- Specials/SpecialListFiles.php
  {
    name    = "index php special listfiles",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Listfiles(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      ilsearch = T.nullable(T.string({ max=512 })),
      ilshowall = T.nullable(T.string({ max=512 })),
      user = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special listfiles post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Listfiles(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      ilsearch = T.nullable(T.string({ max=512 })),
      ilshowall = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      user = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Listgrants (SpecialListGrants, extends=SpecialPage, method=none) -- Specials/SpecialListGrants.php
  {
    name    = "index php special listgrants",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Listgrants(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Listgrouprights (SpecialListGroupRights, extends=SpecialPage, method=none) -- Specials/SpecialListGroupRights.php
  {
    name    = "index php special listgrouprights",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Listgrouprights(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Listredirects (SpecialListRedirects, extends=QueryPage, method=query_page_standard) -- Specials/SpecialListRedirects.php
  {
    name    = "index php special listredirects",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Listredirects(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Listusers (SpecialListUsers, extends=IncludableSpecialPage, method=none) -- Specials/SpecialListUsers.php
  -- Lockdb (SpecialLockdb, extends=FormSpecialPage, method=form_fields) -- Specials/SpecialLockdb.php
  {
    name    = "index php special lockdb",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Lockdb(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  {
    name    = "index php special lockdb post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Lockdb(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpConfirm = T.nullable(T.string({ max=8 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
    }),
  },
  -- Log (SpecialLog, extends=SpecialPage, method=heuristic) -- Specials/SpecialLog.php
  {
    name    = "index php special log post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Log(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      excludetempacct = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpdate = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Lonelypages (SpecialLonelyPages, extends=PageQueryPage, method=query_page_standard) -- Specials/SpecialLonelyPages.php
  {
    name    = "index php special lonelypages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Lonelypages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Longpages (SpecialLongPages, extends=SpecialShortPages, method=query_page_standard) -- Specials/SpecialLongPages.php
  {
    name    = "index php special longpages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Longpages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- MIMEsearch (SpecialMIMESearch, extends=QueryPage, method=query_page_standard) -- Specials/SpecialMIMESearch.php
  -- MediaStatistics (SpecialMediaStatistics, extends=QueryPage, method=query_page_standard) -- Specials/SpecialMediaStatistics.php
  {
    name    = "index php special mediastatistics",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:MediaStatistics(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- MergeHistory (SpecialMergeHistory, extends=SpecialPage, method=heuristic) -- Specials/SpecialMergeHistory.php
  {
    name    = "index php special mergehistory post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:MergeHistory(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      dest = T.nullable(T.string({ max=512 })),
      destID = T.nullable(T.string({ max=512 })),
      mergepoint = T.nullable(T.string({ max=512 })),
      mergepointold = T.nullable(T.string({ max=512 })),
      submitted = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      targetID = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpComment = T.nullable(T.string({ max=1024 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Mostcategories (SpecialMostCategories, extends=QueryPage, method=query_page_standard) -- Specials/SpecialMostCategories.php
  {
    name    = "index php special mostcategories",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Mostcategories(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Mostimages (SpecialMostImages, extends=ImageQueryPage, method=query_page_standard) -- Specials/SpecialMostImages.php
  {
    name    = "index php special mostimages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Mostimages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Mostinterwikis (SpecialMostInterwikis, extends=QueryPage, method=query_page_standard) -- Specials/SpecialMostInterwikis.php
  {
    name    = "index php special mostinterwikis",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Mostinterwikis(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Mostlinked (SpecialMostLinked, extends=QueryPage, method=query_page_standard) -- Specials/SpecialMostLinked.php
  {
    name    = "index php special mostlinked",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Mostlinked(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Mostlinkedcategories (SpecialMostLinkedCategories, extends=QueryPage, method=query_page_standard) -- Specials/SpecialMostLinkedCategories.php
  {
    name    = "index php special mostlinkedcategories",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Mostlinkedcategories(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Mostlinkedtemplates (SpecialMostLinkedTemplates, extends=QueryPage, method=query_page_standard) -- Specials/SpecialMostLinkedTemplates.php
  {
    name    = "index php special mostlinkedtemplates",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Mostlinkedtemplates(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Mostrevisions (SpecialMostRevisions, extends=SpecialFewestRevisions, method=query_page_standard) -- Specials/SpecialMostRevisions.php
  {
    name    = "index php special mostrevisions",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Mostrevisions(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Movepage (SpecialMovePage, extends=UnlistedSpecialPage, method=heuristic) -- Specials/SpecialMovePage.php
  {
    name    = "index php special movepage",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Movepage(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      action = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      wpDeleteAndMove = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFixRedirects = T.nullable(T.string({ max=512 })),
      wpLeaveRedirect = T.nullable(T.string({ max=512 })),
      wpMove = T.nullable(T.string({ max=512 })),
      wpMoveOverProtection = T.nullable(T.string({ max=512 })),
      wpMoveOverSharedFile = T.nullable(T.string({ max=512 })),
      wpMovesubpages = T.nullable(T.string({ max=512 })),
      wpMovetalk = T.nullable(T.string({ max=512 })),
      ['wpMovetalk-field'] = T.nullable(T.string({ max=512 })),
      wpNewTitle = T.nullable(T.string({ max=512 })),
      wpNewTitleMain = T.nullable(T.string({ max=512 })),
      wpNewTitleNs = T.nullable(T.string({ max=512 })),
      wpOldTitle = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpReasonList = T.nullable(T.string({ max=1024 })),
      wpWatch = T.nullable(T.string({ max=512 })),
      wpWatchlistExpiry = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special movepage post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Movepage(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpDeleteAndMove = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFixRedirects = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpLeaveRedirect = T.nullable(T.string({ max=512 })),
      wpMove = T.nullable(T.string({ max=512 })),
      wpMoveOverProtection = T.nullable(T.string({ max=512 })),
      wpMoveOverSharedFile = T.nullable(T.string({ max=512 })),
      wpMovesubpages = T.nullable(T.string({ max=512 })),
      wpMovetalk = T.nullable(T.string({ max=512 })),
      ['wpMovetalk-field'] = T.nullable(T.string({ max=512 })),
      wpNewTitle = T.nullable(T.string({ max=512 })),
      wpNewTitleMain = T.nullable(T.string({ max=512 })),
      wpNewTitleNs = T.nullable(T.string({ max=512 })),
      wpOldTitle = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpReasonList = T.nullable(T.string({ max=1024 })),
      wpWatch = T.nullable(T.string({ max=512 })),
      wpWatchlistExpiry = T.nullable(T.string({ max=512 })),
    }),
  },
  -- MyLanguage (SpecialMyLanguage, extends=RedirectSpecialArticle, method=redirect_passthrough) -- Specials/SpecialMyLanguage.php
  {
    name    = "index php special mylanguage",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:MyLanguage(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Mycontributions (SpecialMycontributions, extends=RedirectSpecialPage, method=redirect_passthrough) -- Specials/Redirects/SpecialMycontributions.php
  {
    name    = "index php special mycontributions",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Mycontributions(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Mylog (SpecialMylog, extends=RedirectSpecialPage, method=redirect_passthrough) -- Specials/Redirects/SpecialMylog.php
  {
    name    = "index php special mylog",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Mylog(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Mypage (SpecialMypage, extends=RedirectSpecialArticle, method=redirect_passthrough) -- Specials/Redirects/SpecialMypage.php
  {
    name    = "index php special mypage",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Mypage(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Mytalk (SpecialMytalk, extends=RedirectSpecialArticle, method=redirect_passthrough) -- Specials/Redirects/SpecialMytalk.php
  {
    name    = "index php special mytalk",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Mytalk(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Myuploads (SpecialMyuploads, extends=RedirectSpecialPage, method=redirect_passthrough) -- Specials/Redirects/SpecialMyuploads.php
  {
    name    = "index php special myuploads",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Myuploads(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- NamespaceInfo (SpecialNamespaceInfo, extends=SpecialPage, method=none) -- Specials/SpecialNamespaceInfo.php
  {
    name    = "index php special namespaceinfo",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:NamespaceInfo(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- NewSection (SpecialNewSection, extends=RedirectSpecialPage, method=redirect_passthrough) -- Specials/SpecialNewSection.php
  {
    name    = "index php special newsection",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:NewSection(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Newimages (SpecialNewFiles, extends=IncludableSpecialPage, method=none) -- Specials/SpecialNewFiles.php
  {
    name    = "index php special newimages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Newimages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Newpages (SpecialNewPages, extends=IncludableSpecialPage, method=none) -- Specials/SpecialNewPages.php
  -- PageData (SpecialPageData, extends=UnlistedSpecialPage, method=none) -- Specials/SpecialPageData.php
  {
    name    = "index php special pagedata",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:PageData(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- PageHistory (SpecialPageHistory, extends=SpecialRedirectWithAction, method=redirect_passthrough) -- Specials/SpecialPageHistory.php
  {
    name    = "index php special pagehistory",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:PageHistory(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- PageInfo (SpecialPageInfo, extends=SpecialRedirectWithAction, method=redirect_passthrough) -- Specials/SpecialPageInfo.php
  {
    name    = "index php special pageinfo",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:PageInfo(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- PagesWithProp (SpecialPagesWithProp, extends=QueryPage, method=query_page_standard) -- Specials/SpecialPagesWithProp.php
  -- PasswordPolicies (SpecialPasswordPolicies, extends=SpecialPage, method=none) -- Specials/SpecialPasswordPolicies.php
  {
    name    = "index php special passwordpolicies",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:PasswordPolicies(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- PasswordReset (SpecialPasswordReset, extends=FormSpecialPage, method=form_fields) -- Specials/SpecialPasswordReset.php
  {
    name    = "index php special passwordreset",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:PasswordReset(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  {
    name    = "index php special passwordreset post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:PasswordReset(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpEmail = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpUsername = T.nullable(T.string({ max=512 })),
    }),
  },
  -- PermanentLink (SpecialPermanentLink, extends=RedirectSpecialPage, method=redirect_passthrough) -- Specials/SpecialPermanentLink.php
  {
    name    = "index php special permanentlink",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:PermanentLink(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Preferences (SpecialPreferences, extends=SpecialPage, method=form_fields) -- Specials/SpecialPreferences.php
  {
    name    = "index php special preferences",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Preferences(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  {
    name    = "index php special preferences post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Preferences(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpServerTime = T.nullable(T.string({ max=512 })),
      wpccmeonemails = T.nullable(T.string({ max=8 })),
      wpcommoncssjs = T.nullable(T.string({ max=512 })),
      ['wpcustomcssjs-safemode'] = T.nullable(T.string({ max=512 })),
      wpdate = T.nullable(T.string({ max=512 })),
      ['wpdiff-type'] = T.nullable(T.string({ max=512 })),
      wpdiffonly = T.nullable(T.string({ max=8 })),
      wpdisablemail = T.nullable(T.string({ max=8 })),
      wpdownloaduserdata = T.nullable(T.string({ max=512 })),
      wpeditcount = T.nullable(T.string({ max=512 })),
      wpeditfont = T.nullable(T.string({ max=10, enum={ ['monospace']=true, ['sans-serif']=true, ['serif']=true } })),
      wpeditondblclick = T.nullable(T.string({ max=8 })),
      wpeditrecovery = T.nullable(T.string({ max=8 })),
      wpeditsectiononrightclick = T.nullable(T.string({ max=8 })),
      wpeditwatchlist = T.nullable(T.string({ max=512 })),
      wpeditwatchlistlabels = T.nullable(T.string({ max=512 })),
      ['wpemail-allow-new-users'] = T.nullable(T.string({ max=8 })),
      ['wpemail-blacklist'] = T.nullable(T.string({ max=512 })),
      wpemailaddress = T.nullable(T.string({ max=512 })),
      wpemailauthentication = T.nullable(T.string({ max=512 })),
      wpenotifminoredits = T.nullable(T.string({ max=8 })),
      wpenotifrevealaddr = T.nullable(T.string({ max=8 })),
      wpenotifusertalkpages = T.nullable(T.string({ max=8 })),
      wpenotifwatchlistpages = T.nullable(T.string({ max=8 })),
      wpextendwatchlist = T.nullable(T.string({ max=8 })),
      wpfancysig = T.nullable(T.string({ max=8 })),
      wpforceeditsummary = T.nullable(T.string({ max=8 })),
      wpforcesafemode = T.nullable(T.string({ max=8 })),
      wpgender = T.nullable(T.string({ max=7, enum={ ['unknown']=true, ['female']=true, ['male']=true } })),
      wphidecategorization = T.nullable(T.string({ max=8 })),
      wphideminor = T.nullable(T.string({ max=8 })),
      wphidepatrolled = T.nullable(T.string({ max=8 })),
      wpimagesize = T.nullable(T.string({ max=512 })),
      wplanguage = T.nullable(T.string({ max=512 })),
      ['wpminerva-theme'] = T.nullable(T.string({ max=512 })),
      wpminordefault = T.nullable(T.string({ max=8 })),
      wpnewpageshidepatrolled = T.nullable(T.string({ max=8 })),
      wpnickname = T.nullable(T.string({ max=512 })),
      wpnorollbackdiff = T.nullable(T.string({ max=8 })),
      wpnowlocal = T.nullable(T.string({ max=512 })),
      wpnowserver = T.nullable(T.string({ max=512 })),
      wpoldsig = T.nullable(T.string({ max=512 })),
      wppassword = T.nullable(T.string({ max=512 })),
      wpprefershttps = T.nullable(T.string({ max=8 })),
      wppreviewonfirst = T.nullable(T.string({ max=8 })),
      wppreviewontop = T.nullable(T.string({ max=8 })),
      ['wppst-cssjs'] = T.nullable(T.string({ max=512 })),
      wprcdays = T.nullable(T.number_query({ integer=true })),
      ['wprcenhancedfilters-disable'] = T.nullable(T.string({ max=8 })),
      ['wprcfilters-limit'] = T.nullable(T.string({ max=512 })),
      ['wprcfilters-rc-collapsed'] = T.nullable(T.string({ max=512 })),
      ['wprcfilters-saved-queries'] = T.nullable(T.string({ max=512 })),
      ['wprcfilters-saved-queries-versionbackup'] = T.nullable(T.string({ max=512 })),
      ['wprcfilters-wl-collapsed'] = T.nullable(T.string({ max=512 })),
      ['wprcfilters-wl-saved-queries'] = T.nullable(T.string({ max=512 })),
      ['wprcfilters-wl-saved-queries-versionbackup'] = T.nullable(T.string({ max=512 })),
      wprclimit = T.nullable(T.number_query({ integer=true })),
      wprealname = T.nullable(T.string({ max=512 })),
      wpregistrationdate = T.nullable(T.string({ max=512 })),
      wprequireemail = T.nullable(T.string({ max=8 })),
      wprestoreprefs = T.nullable(T.string({ max=512 })),
      ['wpsearch-match-redirect'] = T.nullable(T.string({ max=512 })),
      ['wpsearch-special-page'] = T.nullable(T.string({ max=512 })),
      ['wpsearch-thumbnail-extra-namespaces'] = T.nullable(T.string({ max=8 })),
      wpsearchlimit = T.nullable(T.number_query({ integer=true })),
      wpshowhiddencats = T.nullable(T.string({ max=8 })),
      wpshownumberswatching = T.nullable(T.string({ max=8 })),
      wpshowrollbackconfirmation = T.nullable(T.string({ max=8 })),
      wpskin = T.nullable(T.string({ max=512 })),
      ['wpskin-responsive'] = T.nullable(T.string({ max=8 })),
      wpthumbsize = T.nullable(T.string({ max=512 })),
      wptimecorrection = T.nullable(T.string({ max=512 })),
      wpunderline = T.nullable(T.string({ max=512 })),
      wpuseeditwarning = T.nullable(T.string({ max=8 })),
      wpuselivepreview = T.nullable(T.string({ max=8 })),
      wpusenewrc = T.nullable(T.string({ max=8 })),
      wpusergroups = T.nullable(T.string({ max=512 })),
      ['wpusergroups-disabled'] = T.nullable(T.string({ max=512 })),
      wpusername = T.nullable(T.string({ max=512 })),
      wpvariant = T.nullable(T.string({ max=512 })),
      ['wpvector-appearance-pinned'] = T.nullable(T.string({ max=512 })),
      ['wpvector-font-size'] = T.nullable(T.string({ max=1, enum={ ['0']=true, ['1']=true, ['2']=true } })),
      ['wpvector-limited-width'] = T.nullable(T.string({ max=8 })),
      ['wpvector-main-menu-pinned'] = T.nullable(T.string({ max=512 })),
      ['wpvector-page-tools-pinned'] = T.nullable(T.string({ max=512 })),
      ['wpvector-theme'] = T.nullable(T.string({ max=5, enum={ ['day']=true, ['night']=true, ['os']=true } })),
      ['wpvector-toc-pinned'] = T.nullable(T.string({ max=512 })),
      wpwatchcreations = T.nullable(T.string({ max=8 })),
      ['wpwatchcreations-expiry'] = T.nullable(T.string({ max=512 })),
      wpwatchdefault = T.nullable(T.string({ max=8 })),
      ['wpwatchdefault-expiry'] = T.nullable(T.string({ max=512 })),
      wpwatchdeletion = T.nullable(T.string({ max=8 })),
      wpwatchlistdays = T.nullable(T.number_query({ integer=true })),
      wpwatchlisthideanons = T.nullable(T.string({ max=8 })),
      wpwatchlisthidebots = T.nullable(T.string({ max=8 })),
      wpwatchlisthidecategorization = T.nullable(T.string({ max=8 })),
      wpwatchlisthideliu = T.nullable(T.string({ max=8 })),
      wpwatchlisthideminor = T.nullable(T.string({ max=8 })),
      wpwatchlisthideown = T.nullable(T.string({ max=8 })),
      wpwatchlisthidepatrolled = T.nullable(T.string({ max=8 })),
      wpwatchlistlabelonboarding = T.nullable(T.string({ max=512 })),
      wpwatchlistreloadautomatically = T.nullable(T.string({ max=8 })),
      wpwatchlisttoken = T.nullable(T.string({ max=512 })),
      ['wpwatchlisttoken-info'] = T.nullable(T.string({ max=512 })),
      wpwatchlistunwatchlinks = T.nullable(T.string({ max=8 })),
      wpwatchmoves = T.nullable(T.string({ max=8 })),
      wpwatchrollback = T.nullable(T.string({ max=8 })),
      ['wpwatchrollback-expiry'] = T.nullable(T.string({ max=512 })),
      wpwatchuploads = T.nullable(T.string({ max=8 })),
      ['wpwlenhancedfilters-disable'] = T.nullable(T.string({ max=8 })),
      wpwllimit = T.nullable(T.number_query({ integer=true })),
    }),
  },
  -- Prefixindex (SpecialPrefixIndex, extends=SpecialAllPages, method=heuristic) -- Specials/SpecialPrefixIndex.php
  {
    name    = "index php special prefixindex",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Prefixindex(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      from = T.nullable(T.string({ max=512 })),
      hideredirects = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      prefix = T.nullable(T.string({ max=512 })),
      stripprefix = T.nullable(T.string({ max=512 })),
      to = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special prefixindex post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Prefixindex(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      from = T.nullable(T.string({ max=512 })),
      hideredirects = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      prefix = T.nullable(T.string({ max=512 })),
      stripprefix = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      to = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- ProtectPage (SpecialProtectPage, extends=SpecialRedirectWithAction, method=redirect_passthrough) -- Specials/SpecialProtectPage.php
  {
    name    = "index php special protectpage",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:ProtectPage(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Protectedpages (SpecialProtectedPages, extends=SpecialPage, method=heuristic) -- Specials/SpecialProtectedPages.php
  {
    name    = "index php special protectedpages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Protectedpages(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      level = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      size = T.nullable(T.string({ max=512 })),
      ['size-mode'] = T.nullable(T.string({ max=512 })),
      type = T.nullable(T.string({ max=512 })),
      wpfilters = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special protectedpages post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Protectedpages(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      level = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      size = T.nullable(T.string({ max=512 })),
      ['size-mode'] = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      type = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpfilters = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Protectedtitles (SpecialProtectedTitles, extends=SpecialPage, method=heuristic) -- Specials/SpecialProtectedTitles.php
  {
    name    = "index php special protectedtitles post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Protectedtitles(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      level = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Purge (SpecialPurge, extends=SpecialRedirectWithAction, method=redirect_passthrough) -- Specials/SpecialPurge.php
  {
    name    = "index php special purge",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Purge(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- RandomInCategory (SpecialRandomInCategory, extends=FormSpecialPage, method=form_fields) -- Specials/SpecialRandomInCategory.php
  {
    name    = "index php special randomincategory",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:RandomInCategory(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  {
    name    = "index php special randomincategory post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:RandomInCategory(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpcategory = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Randompage (SpecialRandomPage, extends=SpecialPage, method=heuristic) -- Specials/SpecialRandomPage.php
  {
    name    = "index php special randompage",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Randompage(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      action = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special randompage post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Randompage(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Randomredirect (SpecialRandomRedirect, extends=SpecialRandomPage, method=query_page_standard) -- Specials/SpecialRandomRedirect.php
  {
    name    = "index php special randomredirect",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Randomredirect(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Randomrootpage (SpecialRandomRootPage, extends=SpecialRandomPage, method=query_page_standard) -- Specials/SpecialRandomRootPage.php
  {
    name    = "index php special randomrootpage",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Randomrootpage(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Recentchanges (SpecialRecentChanges, extends=ChangesListSpecialPage, method=heuristic) -- Specials/SpecialRecentChanges.php
  {
    name    = "index php special recentchanges",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Recentchanges(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      action = T.nullable(T.string({ max=512 })),
      enable_partitioning = T.nullable(T.string({ max=512 })),
      feed = T.nullable(T.string({ max=512 })),
      peek = T.nullable(T.string({ max=512 })),
      rcfilters = T.nullable(T.string({ max=512 })),
      urlversion = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special recentchanges post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Recentchanges(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      enable_partitioning = T.nullable(T.string({ max=512 })),
      feed = T.nullable(T.string({ max=512 })),
      peek = T.nullable(T.string({ max=512 })),
      rcfilters = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      urlversion = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Recentchangeslinked (SpecialRecentChangesLinked, extends=SpecialRecentChanges, method=heuristic) -- Specials/SpecialRecentChangesLinked.php
  {
    name    = "index php special recentchangeslinked post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Recentchangeslinked(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      enable_partitioning = T.nullable(T.string({ max=512 })),
      feed = T.nullable(T.string({ max=512 })),
      peek = T.nullable(T.string({ max=512 })),
      rcfilters = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      urlversion = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Redirect (SpecialRedirect, extends=FormSpecialPage, method=form_fields) -- Specials/SpecialRedirect.php
  {
    name    = "index php special redirect post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Redirect(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wptype = T.nullable(T.string({ max=8, enum={ ['user']=true, ['page']=true, ['revision']=true, ['file']=true, ['logid']=true } })),
      wpvalue = T.nullable(T.string({ max=512 })),
    }),
  },
  -- RemoveCredentials (SpecialRemoveCredentials, extends=SpecialChangeCredentials, method=heuristic) -- Specials/SpecialRemoveCredentials.php
  {
    name    = "index php special removecredentials",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:RemoveCredentials(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special removecredentials post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:RemoveCredentials(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Renameuser (SpecialRenameUser, extends=SpecialPage, method=heuristic) -- Specials/SpecialRenameUser.php
  {
    name    = "index php special renameuser",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Renameuser(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      confirmaction = T.nullable(T.string({ max=512 })),
      forceglobaldetach = T.nullable(T.string({ max=512 })),
      movepages = T.nullable(T.string({ max=512 })),
      newusername = T.nullable(T.string({ max=512 })),
      oldusername = T.nullable(T.string({ max=512 })),
      reason = T.nullable(T.string({ max=1024 })),
      suppressredirect = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special renameuser post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Renameuser(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      confirmaction = T.nullable(T.string({ max=512 })),
      forceglobaldetach = T.nullable(T.string({ max=512 })),
      movepages = T.nullable(T.string({ max=512 })),
      newusername = T.nullable(T.string({ max=512 })),
      oldusername = T.nullable(T.string({ max=512 })),
      reason = T.nullable(T.string({ max=1024 })),
      suppressredirect = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- ResetTokens (SpecialResetTokens, extends=FormSpecialPage, method=form_fields) -- Specials/SpecialResetTokens.php
  {
    name    = "index php special resettokens",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:ResetTokens(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  {
    name    = "index php special resettokens post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:ResetTokens(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wptokens = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Revisiondelete (SpecialRevisionDelete, extends=UnlistedSpecialPage, method=heuristic) -- Specials/SpecialRevisionDelete.php
  {
    name    = "index php special revisiondelete",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Revisiondelete(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      file = T.nullable(T.string({ max=512 })),
      ids = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      token = T.nullable(T.string({ max=512 })),
      type = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpHideComment = T.nullable(T.string({ max=1024 })),
      wpHidePrimary = T.nullable(T.string({ max=512 })),
      wpHideRestricted = T.nullable(T.string({ max=512 })),
      wpHideUser = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpReasonDropDown = T.nullable(T.string({ max=1024 })),
      wpRevDeleteReasonList = T.nullable(T.string({ max=1024 })),
      wpSubmit = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special revisiondelete post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Revisiondelete(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      file = T.nullable(T.string({ max=512 })),
      ids = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      token = T.nullable(T.string({ max=512 })),
      type = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpHideComment = T.nullable(T.string({ max=1024 })),
      wpHidePrimary = T.nullable(T.string({ max=512 })),
      wpHideRestricted = T.nullable(T.string({ max=512 })),
      wpHideUser = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpReasonDropDown = T.nullable(T.string({ max=1024 })),
      wpRevDeleteReasonList = T.nullable(T.string({ max=1024 })),
      wpSubmit = T.nullable(T.string({ max=512 })),
    }),
  },
  -- RunJobs (SpecialRunJobs, extends=UnlistedSpecialPage, method=none) -- Specials/SpecialRunJobs.php
  {
    name    = "index php special runjobs",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:RunJobs(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Shortpages (SpecialShortPages, extends=QueryPage, method=query_page_standard) -- Specials/SpecialShortPages.php
  {
    name    = "index php special shortpages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Shortpages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Specialpages (SpecialSpecialPages, extends=UnlistedSpecialPage, method=none) -- Specials/SpecialSpecialPages.php
  {
    name    = "index php special specialpages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Specialpages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Statistics (SpecialStatistics, extends=SpecialPage, method=none) -- Specials/SpecialStatistics.php
  {
    name    = "index php special statistics",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Statistics(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Tags (SpecialTags, extends=SpecialPage, method=heuristic) -- Specials/SpecialTags.php
  {
    name    = "index php special tags",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Tags(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      tag = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special tags post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Tags(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      tag = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- TalkPage (SpecialTalkPage, extends=FormSpecialPage, method=form_fields) -- Specials/Redirects/SpecialTalkPage.php
  {
    name    = "index php special talkpage",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:TalkPage(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  {
    name    = "index php special talkpage post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:TalkPage(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      target = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- TrackingCategories (SpecialTrackingCategories, extends=SpecialPage, method=none) -- Specials/SpecialTrackingCategories.php
  {
    name    = "index php special trackingcategories",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:TrackingCategories(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Unblock (SpecialUnblock, extends=SpecialPage, method=heuristic) -- Specials/SpecialUnblock.php
  {
    name    = "index php special unblock",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Unblock(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      ip = T.nullable(T.string({ max=512 })),
      usecodex = T.nullable(T.string({ max=512 })),
      wpBlockAddress = T.nullable(T.string({ max=512 })),
      wpTarget = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special unblock post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Unblock(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      ip = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      usecodex = T.nullable(T.string({ max=512 })),
      wpBlockAddress = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpTarget = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Uncategorizedcategories (SpecialUncategorizedCategories, extends=SpecialUncategorizedPages, method=query_page_standard) -- Specials/SpecialUncategorizedCategories.php
  {
    name    = "index php special uncategorizedcategories",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Uncategorizedcategories(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Uncategorizedimages (SpecialUncategorizedImages, extends=ImageQueryPage, method=query_page_standard) -- Specials/SpecialUncategorizedImages.php
  {
    name    = "index php special uncategorizedimages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Uncategorizedimages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Uncategorizedpages (SpecialUncategorizedPages, extends=PageQueryPage, method=query_page_standard) -- Specials/SpecialUncategorizedPages.php
  {
    name    = "index php special uncategorizedpages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Uncategorizedpages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Uncategorizedtemplates (SpecialUncategorizedTemplates, extends=SpecialUncategorizedPages, method=query_page_standard) -- Specials/SpecialUncategorizedTemplates.php
  {
    name    = "index php special uncategorizedtemplates",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Uncategorizedtemplates(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Undelete (SpecialUndelete, extends=SpecialPage, method=heuristic) -- Specials/SpecialUndelete.php
  {
    name    = "index php special undelete",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Undelete(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      action = T.nullable(T.string({ max=512 })),
      diff = T.nullable(T.string({ max=512 })),
      diffonly = T.nullable(T.string({ max=512 })),
      file = T.nullable(T.string({ max=512 })),
      fuzzy = T.nullable(T.string({ max=512 })),
      historyoffset = T.nullable(T.string({ max=512 })),
      invert = T.nullable(T.string({ max=512 })),
      prefix = T.nullable(T.string({ max=512 })),
      preview = T.nullable(T.string({ max=512 })),
      restore = T.nullable(T.string({ max=512 })),
      revdel = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      timestamp = T.nullable(T.string({ max=512 })),
      token = T.nullable(T.string({ max=512 })),
      undeletetalk = T.nullable(T.string({ max=512 })),
      wpComment = T.nullable(T.string({ max=1024 })),
      wpCommentList = T.nullable(T.string({ max=1024 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpUnsuppress = T.nullable(T.string({ max=512 })),
      wpWatch = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special undelete post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Undelete(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      diff = T.nullable(T.string({ max=512 })),
      diffonly = T.nullable(T.string({ max=512 })),
      file = T.nullable(T.string({ max=512 })),
      fuzzy = T.nullable(T.string({ max=512 })),
      historyoffset = T.nullable(T.string({ max=512 })),
      invert = T.nullable(T.string({ max=512 })),
      prefix = T.nullable(T.string({ max=512 })),
      preview = T.nullable(T.string({ max=512 })),
      restore = T.nullable(T.string({ max=512 })),
      revdel = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      timestamp = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      token = T.nullable(T.string({ max=512 })),
      undeletetalk = T.nullable(T.string({ max=512 })),
      wpComment = T.nullable(T.string({ max=1024 })),
      wpCommentList = T.nullable(T.string({ max=1024 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpUnsuppress = T.nullable(T.string({ max=512 })),
      wpWatch = T.nullable(T.string({ max=512 })),
    }),
  },
  -- UnlinkAccounts (SpecialUnlinkAccounts, extends=AuthManagerSpecialPage, method=heuristic) -- Specials/SpecialUnlinkAccounts.php
  {
    name    = "index php special unlinkaccounts",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:UnlinkAccounts(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special unlinkaccounts post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:UnlinkAccounts(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Unlockdb (SpecialUnlockdb, extends=FormSpecialPage, method=form_fields) -- Specials/SpecialUnlockdb.php
  {
    name    = "index php special unlockdb",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Unlockdb(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  {
    name    = "index php special unlockdb post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Unlockdb(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpConfirm = T.nullable(T.string({ max=8 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Unusedcategories (SpecialUnusedCategories, extends=QueryPage, method=query_page_standard) -- Specials/SpecialUnusedCategories.php
  {
    name    = "index php special unusedcategories",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Unusedcategories(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Unusedimages (SpecialUnusedImages, extends=ImageQueryPage, method=query_page_standard) -- Specials/SpecialUnusedImages.php
  {
    name    = "index php special unusedimages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Unusedimages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Unusedtemplates (SpecialUnusedTemplates, extends=QueryPage, method=query_page_standard) -- Specials/SpecialUnusedTemplates.php
  {
    name    = "index php special unusedtemplates",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Unusedtemplates(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Unwatchedpages (SpecialUnwatchedPages, extends=QueryPage, method=query_page_standard) -- Specials/SpecialUnwatchedPages.php
  {
    name    = "index php special unwatchedpages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Unwatchedpages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Upload (SpecialUpload, extends=SpecialPage, method=heuristic) -- Specials/SpecialUpload.php
  {
    name    = "index php special upload",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Upload(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      wpCacheKey = T.nullable(T.string({ max=512 })),
      wpCancelUpload = T.nullable(T.string({ max=512 })),
      wpChangeTags = T.nullable(T.string({ max=512 })),
      wpDestFile = T.nullable(T.string({ max=512 })),
      wpDestFileWarningAck = T.nullable(T.string({ max=512 })),
      wpDestUrl = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpForReUpload = T.nullable(T.string({ max=512 })),
      wpIgnoreWarning = T.nullable(T.string({ max=512 })),
      wpLicense = T.nullable(T.string({ max=512 })),
      wpReUpload = T.nullable(T.string({ max=512 })),
      wpSourceType = T.nullable(T.string({ max=512 })),
      wpUpload = T.nullable(T.string({ max=512 })),
      wpUploadCopyStatus = T.nullable(T.string({ max=512 })),
      wpUploadDescription = T.nullable(T.string({ max=65536 })),
      wpUploadFile = T.nullable(T.string({ max=512 })),
      wpUploadIgnoreWarning = T.nullable(T.string({ max=512 })),
      wpUploadSource = T.nullable(T.string({ max=512 })),
      wpWatchthis = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special upload post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Upload(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    max_body = 105906176,
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wpCacheKey = T.nullable(T.string({ max=512 })),
      wpCancelUpload = T.nullable(T.string({ max=512 })),
      wpChangeTags = T.nullable(T.string({ max=512 })),
      wpDestFile = T.nullable(T.string({ max=512 })),
      wpDestFileWarningAck = T.nullable(T.string({ max=512 })),
      wpDestUrl = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpForReUpload = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpIgnoreWarning = T.nullable(T.string({ max=512 })),
      wpLicense = T.nullable(T.string({ max=512 })),
      wpReUpload = T.nullable(T.string({ max=512 })),
      wpSourceType = T.nullable(T.string({ max=512 })),
      wpUpload = T.nullable(T.string({ max=512 })),
      wpUploadCopyStatus = T.nullable(T.string({ max=512 })),
      wpUploadDescription = T.nullable(T.string({ max=65536 })),
      wpUploadFile = T.nullable(T.string({ max=512 })),
      wpUploadIgnoreWarning = T.nullable(T.string({ max=512 })),
      wpUploadSource = T.nullable(T.string({ max=512 })),
      wpWatchthis = T.nullable(T.string({ max=512 })),
    }),
  },
  -- UploadStash (SpecialUploadStash, extends=UnlistedSpecialPage, method=none) -- Specials/SpecialUploadStash.php
  {
    name    = "index php special uploadstash",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:UploadStash(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Userlogin (SpecialUserLogin, extends=LoginSignupSpecialPage, method=heuristic) -- Specials/SpecialUserLogin.php
  {
    name    = "index php special userlogin",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Userlogin(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      action = T.nullable(T.string({ max=512 })),
      alwaysShowLogin = T.nullable(T.string({ max=512 })),
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      error = T.nullable(T.string({ max=512 })),
      force = T.nullable(T.string({ max=512 })),
      fromhttp = T.nullable(T.string({ max=512 })),
      notice = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      type = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      warning = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
      wpCreateaccount = T.nullable(T.string({ max=512 })),
      wpCreateaccountMail = T.nullable(T.string({ max=512 })),
      wpCreateaccountToken = T.nullable(T.string({ max=512 })),
      wpEmail = T.nullable(T.string({ max=512 })),
      wpForceHttps = T.nullable(T.string({ max=512 })),
      wpFromhttp = T.nullable(T.string({ max=512 })),
      wpLoginToken = T.nullable(T.string({ max=512 })),
      wpName = T.nullable(T.string({ max=512 })),
      wpName1 = T.nullable(T.string({ max=512 })),
      wpName2 = T.nullable(T.string({ max=512 })),
      wpPassword = T.nullable(T.string({ max=512 })),
      wpPassword1 = T.nullable(T.string({ max=512 })),
      wpPassword2 = T.nullable(T.string({ max=512 })),
      wpRealName = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpRemember = T.nullable(T.string({ max=512 })),
      wpRetype = T.nullable(T.string({ max=512 })),
      wploginattempt = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special userlogin post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Userlogin(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      alwaysShowLogin = T.nullable(T.string({ max=512 })),
      authAction = T.nullable(T.string({ max=512 })),
      authUniqueId = T.nullable(T.string({ max=512 })),
      error = T.nullable(T.string({ max=512 })),
      force = T.nullable(T.string({ max=512 })),
      fromhttp = T.nullable(T.string({ max=512 })),
      notice = T.nullable(T.string({ max=512 })),
      returnto = T.nullable(T.string({ max=512 })),
      returntoanchor = T.nullable(T.string({ max=512 })),
      returntoquery = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      type = T.nullable(T.string({ max=512 })),
      uselang = T.nullable(T.string({ max=512 })),
      variant = T.nullable(T.string({ max=512 })),
      warning = T.nullable(T.string({ max=512 })),
      wpAuthToken = T.nullable(T.string({ max=512 })),
      wpCreateaccount = T.nullable(T.string({ max=512 })),
      wpCreateaccountMail = T.nullable(T.string({ max=512 })),
      wpCreateaccountToken = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpEmail = T.nullable(T.string({ max=512 })),
      wpForceHttps = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpFromhttp = T.nullable(T.string({ max=512 })),
      wpLoginToken = T.nullable(T.string({ max=512 })),
      wpName = T.nullable(T.string({ max=512 })),
      wpName1 = T.nullable(T.string({ max=512 })),
      wpName2 = T.nullable(T.string({ max=512 })),
      wpPassword = T.nullable(T.string({ max=512 })),
      wpPassword1 = T.nullable(T.string({ max=512 })),
      wpPassword2 = T.nullable(T.string({ max=512 })),
      wpRealName = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpRemember = T.nullable(T.string({ max=512 })),
      wpRetype = T.nullable(T.string({ max=512 })),
      wploginattempt = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Userlogout (SpecialUserLogout, extends=FormSpecialPage, method=heuristic) -- Specials/SpecialUserLogout.php
  {
    name    = "index php special userlogout",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Userlogout(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      wasTempUser = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special userlogout post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Userlogout(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      title = T.nullable(T.string({ max=512 })),
      wasTempUser = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Userrights (SpecialUserRights, extends=UserGroupsSpecialPage, method=heuristic) -- Specials/SpecialUserRights.php
  {
    name    = "index php special userrights",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Userrights(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      saveusergroups = T.nullable(T.string({ max=512 })),
      user = T.nullable(T.string({ max=512 })),
      ['user-reason'] = T.nullable(T.string({ max=1024 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpWatch = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special userrights post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Userrights(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      saveusergroups = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      user = T.nullable(T.string({ max=512 })),
      ['user-reason'] = T.nullable(T.string({ max=1024 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
      wpReason = T.nullable(T.string({ max=1024 })),
      wpWatch = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Version (SpecialVersion, extends=SpecialPage, method=none) -- Specials/SpecialVersion.php
  {
    name    = "index php special version",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Version(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Wantedcategories (SpecialWantedCategories, extends=WantedQueryPage, method=query_page_standard) -- Specials/SpecialWantedCategories.php
  {
    name    = "index php special wantedcategories",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Wantedcategories(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Wantedfiles (SpecialWantedFiles, extends=WantedQueryPage, method=query_page_standard) -- Specials/SpecialWantedFiles.php
  {
    name    = "index php special wantedfiles",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Wantedfiles(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Wantedpages (SpecialWantedPages, extends=WantedQueryPage, method=query_page_standard) -- Specials/SpecialWantedPages.php
  {
    name    = "index php special wantedpages",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Wantedpages(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Wantedtemplates (SpecialWantedTemplates, extends=WantedQueryPage, method=query_page_standard) -- Specials/SpecialWantedTemplates.php
  {
    name    = "index php special wantedtemplates",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Wantedtemplates(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
  -- Watchlist (SpecialWatchlist, extends=ChangesListSpecialPage, method=heuristic) -- Specials/SpecialWatchlist.php
  {
    name    = "index php special watchlist",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Watchlist(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      action = T.nullable(T.string({ max=512 })),
      enable_partitioning = T.nullable(T.string({ max=512 })),
      peek = T.nullable(T.string({ max=512 })),
      rcfilters = T.nullable(T.string({ max=512 })),
      reset = T.nullable(T.string({ max=512 })),
      token = T.nullable(T.string({ max=512 })),
      urlversion = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special watchlist post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Watchlist(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      action = T.nullable(T.string({ max=512 })),
      enable_partitioning = T.nullable(T.string({ max=512 })),
      peek = T.nullable(T.string({ max=512 })),
      rcfilters = T.nullable(T.string({ max=512 })),
      reset = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      token = T.nullable(T.string({ max=512 })),
      urlversion = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- WatchlistLabels (SpecialWatchlistLabels, extends=UnlistedSpecialPage, method=heuristic) -- Specials/SpecialWatchlistLabels.php
  {
    name    = "index php special watchlistlabels",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:WatchlistLabels(?:/.*)?$]],
    query   = T.object(merge(idx_common, {
      asc = T.nullable(T.string({ max=512 })),
      sort = T.nullable(T.string({ max=512 })),
    })),
    no_body = true,
  },
  {
    name    = "index php special watchlistlabels post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:WatchlistLabels(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      asc = T.nullable(T.string({ max=512 })),
      sort = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Whatlinkshere (SpecialWhatLinksHere, extends=FormSpecialPage, method=form_fields) -- Specials/SpecialWhatLinksHere.php
  {
    name    = "index php special whatlinkshere post",
    method  = "POST",
    path    = [[(?i)^/index\.php/Special:Whatlinkshere(?:/.*)?$]],
    content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
    form    = T.object({
      dir = T.nullable(T.string({ max=512 })),
      from = T.nullable(T.string({ max=512 })),
      invert = T.nullable(T.string({ max=8 })),
      limit = T.nullable(T.string({ max=512 })),
      namespace = T.nullable(T.string({ max=512 })),
      offset = T.nullable(T.string({ max=512 })),
      target = T.nullable(T.string({ max=512 })),
      title = T.nullable(T.string({ max=512 })),
      wpEditToken = T.nullable(T.string({ max=512 })),
      wpFormIdentifier = T.nullable(T.string({ max=512 })),
    }),
  },
  -- Withoutinterwiki (SpecialWithoutInterwiki, extends=PageQueryPage, method=query_page_standard) -- Specials/SpecialWithoutInterwiki.php
  {
    name    = "index php special withoutinterwiki",
    method  = "GET",
    path    = [[(?i)^/index\.php/Special:Withoutinterwiki(?:/.*)?$]],
    query   = T.object(idx_common),
    no_body = true,
  },
}

-- Same field sets as the dedicated per-page POST routes above, but as
-- bare form validators (not full route tables) for splicing into the
-- generic "index php post" route's form_schemas - see the comment
-- further up about why query-string-style /index.php?title=Special:X
-- URLs need this too, not just /index.php/Special:X path-style ones.
local mw_special_post_forms = {
  -- Activeusers
  T.object({
    hidebots = T.nullable(T.string({ max=512 })),
    hidesysops = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Allpages
  T.object({
    from = T.nullable(T.string({ max=512 })),
    hideredirects = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    to = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- ApiHelp
  T.object({
    recursivesubmodules = T.nullable(T.string({ max=512 })),
    submodules = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- AuthenticationPopupSuccess
  T.object({
    display = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Block
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpActionRestrictions = T.nullable(T.string({ max=512 })),
    wpAutoBlock = T.nullable(T.string({ max=8 })),
    wpConfirm = T.nullable(T.string({ max=512 })),
    wpCreateAccount = T.nullable(T.string({ max=8 })),
    wpDisableEmail = T.nullable(T.string({ max=8 })),
    wpDisableUTEdit = T.nullable(T.string({ max=8 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpEditingRestriction = T.nullable(T.string({ max=512 })),
    wpExpiry = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpHardBlock = T.nullable(T.string({ max=8 })),
    wpHideUser = T.nullable(T.string({ max=8 })),
    wpNamespaceRestrictions = T.nullable(T.string({ max=512 })),
    wpPageRestrictions = T.nullable(T.string({ max=512 })),
    wpPreviousTarget = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpTarget = T.nullable(T.string({ max=512 })),
    wpWatch = T.nullable(T.string({ max=8 })),
  }),
  -- BlockList
  T.object({
    action = T.nullable(T.string({ max=512 })),
    blockType = T.nullable(T.string({ max=512 })),
    ip = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpOptions = T.nullable(T.string({ max=512 })),
    wpTarget = T.nullable(T.string({ max=512 })),
  }),
  -- Booksources
  T.object({
    isbn = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- BotPasswords
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpappId = T.nullable(T.string({ max=512 })),
    wpgrants = T.nullable(T.string({ max=512 })),
    wpresetPassword = T.nullable(T.string({ max=8 })),
    wprestrictions = T.nullable(T.string({ max=512 })),
  }),
  -- Categories
  T.object({
    from = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- ChangeContentModel
  T.object({
    model = T.nullable(T.string({ max=512 })),
    pagetitle = T.nullable(T.string({ max=512 })),
    reason = T.nullable(T.string({ max=1024 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- ChangeCredentials
  T.object({
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    password = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    retype = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpusername = T.nullable(T.string({ max=512 })),
  }),
  -- Contributions
  T.object({
    associated = T.nullable(T.string({ max=512 })),
    bot = T.nullable(T.string({ max=512 })),
    deletedOnly = T.nullable(T.string({ max=512 })),
    ['end'] = T.nullable(T.string({ max=512 })),
    feed = T.nullable(T.string({ max=512 })),
    hideMinor = T.nullable(T.string({ max=512 })),
    limit = T.nullable(T.string({ max=512 })),
    month = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    newOnly = T.nullable(T.string({ max=512 })),
    nsInvert = T.nullable(T.string({ max=512 })),
    start = T.nullable(T.string({ max=512 })),
    tagInvert = T.nullable(T.string({ max=512 })),
    tagfilter = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    topOnly = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpfilters = T.nullable(T.string({ max=512 })),
    year = T.nullable(T.string({ max=512 })),
  }),
  -- CreateAccount
  T.object({
    action = T.nullable(T.string({ max=512 })),
    alwaysShowLogin = T.nullable(T.string({ max=512 })),
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    error = T.nullable(T.string({ max=512 })),
    force = T.nullable(T.string({ max=512 })),
    fromhttp = T.nullable(T.string({ max=512 })),
    notice = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    warning = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
    wpCreateaccount = T.nullable(T.string({ max=512 })),
    wpCreateaccountMail = T.nullable(T.string({ max=512 })),
    wpCreateaccountToken = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpEmail = T.nullable(T.string({ max=512 })),
    wpForceHttps = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpFromhttp = T.nullable(T.string({ max=512 })),
    wpLoginToken = T.nullable(T.string({ max=512 })),
    wpName = T.nullable(T.string({ max=512 })),
    wpName1 = T.nullable(T.string({ max=512 })),
    wpName2 = T.nullable(T.string({ max=512 })),
    wpPassword = T.nullable(T.string({ max=512 })),
    wpPassword1 = T.nullable(T.string({ max=512 })),
    wpPassword2 = T.nullable(T.string({ max=512 })),
    wpRealName = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpRemember = T.nullable(T.string({ max=512 })),
    wpRetype = T.nullable(T.string({ max=512 })),
    wploginattempt = T.nullable(T.string({ max=512 })),
  }),
  -- DeletedContributions
  T.object({
    associated = T.nullable(T.string({ max=512 })),
    bot = T.nullable(T.string({ max=512 })),
    deletedOnly = T.nullable(T.string({ max=512 })),
    ['end'] = T.nullable(T.string({ max=512 })),
    feed = T.nullable(T.string({ max=512 })),
    hideMinor = T.nullable(T.string({ max=512 })),
    limit = T.nullable(T.string({ max=512 })),
    month = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    newOnly = T.nullable(T.string({ max=512 })),
    nsInvert = T.nullable(T.string({ max=512 })),
    start = T.nullable(T.string({ max=512 })),
    tagInvert = T.nullable(T.string({ max=512 })),
    tagfilter = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    topOnly = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpfilters = T.nullable(T.string({ max=512 })),
    year = T.nullable(T.string({ max=512 })),
  }),
  -- EditTags
  T.object({
    ids = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    type = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpExistingTags = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpRemoveAllTags = T.nullable(T.string({ max=512 })),
    wpSubmit = T.nullable(T.string({ max=512 })),
    wpTagList = T.nullable(T.string({ max=512 })),
    wpTagsToRemove = T.nullable(T.string({ max=512 })),
    wpfilters = T.nullable(T.string({ max=512 })),
  }),
  -- EditWatchlist
  T.object({
    action = T.nullable(T.string({ max=512 })),
    limit = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    watchlistlabels = T.nullable(T.string({ max=512 })),
    ['watchlistlabels-action'] = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpTitles = T.nullable(T.string({ max=512 })),
  }),
  -- Emailuser
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpCCMe = T.nullable(T.string({ max=8 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpFrom = T.nullable(T.string({ max=512 })),
    wpSubject = T.nullable(T.string({ max=512 })),
    wpTarget = T.nullable(T.string({ max=512 })),
    wpText = T.nullable(T.string({ max=1048576 })),
    wpTo = T.nullable(T.string({ max=512 })),
  }),
  -- ExpandTemplates
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpContextTitle = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpGenerateRawHtml = T.nullable(T.string({ max=512 })),
    wpGenerateXml = T.nullable(T.string({ max=512 })),
    wpInput = T.nullable(T.string({ max=512 })),
    wpRemoveComments = T.nullable(T.string({ max=512 })),
    wpRemoveNowiki = T.nullable(T.string({ max=512 })),
  }),
  -- Export
  T.object({
    addcat = T.nullable(T.string({ max=512 })),
    addns = T.nullable(T.string({ max=512 })),
    catname = T.nullable(T.string({ max=512 })),
    curonly = T.nullable(T.string({ max=512 })),
    dir = T.nullable(T.string({ max=512 })),
    exportall = T.nullable(T.string({ max=512 })),
    history = T.nullable(T.string({ max=512 })),
    limit = T.nullable(T.string({ max=512 })),
    listauthors = T.nullable(T.string({ max=512 })),
    nsindex = T.nullable(T.string({ max=512 })),
    offset = T.nullable(T.string({ max=512 })),
    ['pagelink-depth'] = T.nullable(T.string({ max=512 })),
    pages = T.nullable(T.string({ max=512 })),
    templates = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpDownload = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpExportTemplates = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- FileDuplicateSearch
  T.object({
    filename = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Import
  T.object({
    action = T.nullable(T.string({ max=512 })),
    assignKnownUsers = T.nullable(T.string({ max=512 })),
    frompage = T.nullable(T.string({ max=512 })),
    interwiki = T.nullable(T.string({ max=512 })),
    interwikiHistory = T.nullable(T.string({ max=512 })),
    interwikiTemplates = T.nullable(T.string({ max=512 })),
    ['log-comment'] = T.nullable(T.string({ max=1024 })),
    mapping = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    ['pagelink-depth'] = T.nullable(T.string({ max=512 })),
    rootpage = T.nullable(T.string({ max=512 })),
    source = T.nullable(T.string({ max=512 })),
    subproject = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    usernamePrefix = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Interwiki
  T.object({
    action = T.nullable(T.string({ max=512 })),
    prefix = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- LinkAccounts
  T.object({
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Listfiles
  T.object({
    ilsearch = T.nullable(T.string({ max=512 })),
    ilshowall = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    user = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Lockdb
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpConfirm = T.nullable(T.string({ max=8 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
  }),
  -- Log
  T.object({
    excludetempacct = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpdate = T.nullable(T.string({ max=512 })),
  }),
  -- MergeHistory
  T.object({
    action = T.nullable(T.string({ max=512 })),
    dest = T.nullable(T.string({ max=512 })),
    destID = T.nullable(T.string({ max=512 })),
    mergepoint = T.nullable(T.string({ max=512 })),
    mergepointold = T.nullable(T.string({ max=512 })),
    submitted = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    targetID = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpComment = T.nullable(T.string({ max=1024 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Movepage
  T.object({
    action = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpDeleteAndMove = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFixRedirects = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpLeaveRedirect = T.nullable(T.string({ max=512 })),
    wpMove = T.nullable(T.string({ max=512 })),
    wpMoveOverProtection = T.nullable(T.string({ max=512 })),
    wpMoveOverSharedFile = T.nullable(T.string({ max=512 })),
    wpMovesubpages = T.nullable(T.string({ max=512 })),
    wpMovetalk = T.nullable(T.string({ max=512 })),
    ['wpMovetalk-field'] = T.nullable(T.string({ max=512 })),
    wpNewTitle = T.nullable(T.string({ max=512 })),
    wpNewTitleMain = T.nullable(T.string({ max=512 })),
    wpNewTitleNs = T.nullable(T.string({ max=512 })),
    wpOldTitle = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpReasonList = T.nullable(T.string({ max=1024 })),
    wpWatch = T.nullable(T.string({ max=512 })),
    wpWatchlistExpiry = T.nullable(T.string({ max=512 })),
  }),
  -- PasswordReset
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpEmail = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpUsername = T.nullable(T.string({ max=512 })),
  }),
  -- Preferences
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpServerTime = T.nullable(T.string({ max=512 })),
    wpccmeonemails = T.nullable(T.string({ max=8 })),
    wpcommoncssjs = T.nullable(T.string({ max=512 })),
    ['wpcustomcssjs-safemode'] = T.nullable(T.string({ max=512 })),
    wpdate = T.nullable(T.string({ max=512 })),
    ['wpdiff-type'] = T.nullable(T.string({ max=512 })),
    wpdiffonly = T.nullable(T.string({ max=8 })),
    wpdisablemail = T.nullable(T.string({ max=8 })),
    wpdownloaduserdata = T.nullable(T.string({ max=512 })),
    wpeditcount = T.nullable(T.string({ max=512 })),
    wpeditfont = T.nullable(T.string({ max=10, enum={ ['monospace']=true, ['sans-serif']=true, ['serif']=true } })),
    wpeditondblclick = T.nullable(T.string({ max=8 })),
    wpeditrecovery = T.nullable(T.string({ max=8 })),
    wpeditsectiononrightclick = T.nullable(T.string({ max=8 })),
    wpeditwatchlist = T.nullable(T.string({ max=512 })),
    wpeditwatchlistlabels = T.nullable(T.string({ max=512 })),
    ['wpemail-allow-new-users'] = T.nullable(T.string({ max=8 })),
    ['wpemail-blacklist'] = T.nullable(T.string({ max=512 })),
    wpemailaddress = T.nullable(T.string({ max=512 })),
    wpemailauthentication = T.nullable(T.string({ max=512 })),
    wpenotifminoredits = T.nullable(T.string({ max=8 })),
    wpenotifrevealaddr = T.nullable(T.string({ max=8 })),
    wpenotifusertalkpages = T.nullable(T.string({ max=8 })),
    wpenotifwatchlistpages = T.nullable(T.string({ max=8 })),
    wpextendwatchlist = T.nullable(T.string({ max=8 })),
    wpfancysig = T.nullable(T.string({ max=8 })),
    wpforceeditsummary = T.nullable(T.string({ max=8 })),
    wpforcesafemode = T.nullable(T.string({ max=8 })),
    wpgender = T.nullable(T.string({ max=7, enum={ ['unknown']=true, ['female']=true, ['male']=true } })),
    wphidecategorization = T.nullable(T.string({ max=8 })),
    wphideminor = T.nullable(T.string({ max=8 })),
    wphidepatrolled = T.nullable(T.string({ max=8 })),
    wpimagesize = T.nullable(T.string({ max=512 })),
    wplanguage = T.nullable(T.string({ max=512 })),
    ['wpminerva-theme'] = T.nullable(T.string({ max=512 })),
    wpminordefault = T.nullable(T.string({ max=8 })),
    wpnewpageshidepatrolled = T.nullable(T.string({ max=8 })),
    wpnickname = T.nullable(T.string({ max=512 })),
    wpnorollbackdiff = T.nullable(T.string({ max=8 })),
    wpnowlocal = T.nullable(T.string({ max=512 })),
    wpnowserver = T.nullable(T.string({ max=512 })),
    wpoldsig = T.nullable(T.string({ max=512 })),
    wppassword = T.nullable(T.string({ max=512 })),
    wpprefershttps = T.nullable(T.string({ max=8 })),
    wppreviewonfirst = T.nullable(T.string({ max=8 })),
    wppreviewontop = T.nullable(T.string({ max=8 })),
    ['wppst-cssjs'] = T.nullable(T.string({ max=512 })),
    wprcdays = T.nullable(T.number_query({ integer=true })),
    ['wprcenhancedfilters-disable'] = T.nullable(T.string({ max=8 })),
    ['wprcfilters-limit'] = T.nullable(T.string({ max=512 })),
    ['wprcfilters-rc-collapsed'] = T.nullable(T.string({ max=512 })),
    ['wprcfilters-saved-queries'] = T.nullable(T.string({ max=512 })),
    ['wprcfilters-saved-queries-versionbackup'] = T.nullable(T.string({ max=512 })),
    ['wprcfilters-wl-collapsed'] = T.nullable(T.string({ max=512 })),
    ['wprcfilters-wl-saved-queries'] = T.nullable(T.string({ max=512 })),
    ['wprcfilters-wl-saved-queries-versionbackup'] = T.nullable(T.string({ max=512 })),
    wprclimit = T.nullable(T.number_query({ integer=true })),
    wprealname = T.nullable(T.string({ max=512 })),
    wpregistrationdate = T.nullable(T.string({ max=512 })),
    wprequireemail = T.nullable(T.string({ max=8 })),
    wprestoreprefs = T.nullable(T.string({ max=512 })),
    ['wpsearch-match-redirect'] = T.nullable(T.string({ max=512 })),
    ['wpsearch-special-page'] = T.nullable(T.string({ max=512 })),
    ['wpsearch-thumbnail-extra-namespaces'] = T.nullable(T.string({ max=8 })),
    wpsearchlimit = T.nullable(T.number_query({ integer=true })),
    wpshowhiddencats = T.nullable(T.string({ max=8 })),
    wpshownumberswatching = T.nullable(T.string({ max=8 })),
    wpshowrollbackconfirmation = T.nullable(T.string({ max=8 })),
    wpskin = T.nullable(T.string({ max=512 })),
    ['wpskin-responsive'] = T.nullable(T.string({ max=8 })),
    wpthumbsize = T.nullable(T.string({ max=512 })),
    wptimecorrection = T.nullable(T.string({ max=512 })),
    wpunderline = T.nullable(T.string({ max=512 })),
    wpuseeditwarning = T.nullable(T.string({ max=8 })),
    wpuselivepreview = T.nullable(T.string({ max=8 })),
    wpusenewrc = T.nullable(T.string({ max=8 })),
    wpusergroups = T.nullable(T.string({ max=512 })),
    ['wpusergroups-disabled'] = T.nullable(T.string({ max=512 })),
    wpusername = T.nullable(T.string({ max=512 })),
    wpvariant = T.nullable(T.string({ max=512 })),
    ['wpvector-appearance-pinned'] = T.nullable(T.string({ max=512 })),
    ['wpvector-font-size'] = T.nullable(T.string({ max=1, enum={ ['0']=true, ['1']=true, ['2']=true } })),
    ['wpvector-limited-width'] = T.nullable(T.string({ max=8 })),
    ['wpvector-main-menu-pinned'] = T.nullable(T.string({ max=512 })),
    ['wpvector-page-tools-pinned'] = T.nullable(T.string({ max=512 })),
    ['wpvector-theme'] = T.nullable(T.string({ max=5, enum={ ['day']=true, ['night']=true, ['os']=true } })),
    ['wpvector-toc-pinned'] = T.nullable(T.string({ max=512 })),
    wpwatchcreations = T.nullable(T.string({ max=8 })),
    ['wpwatchcreations-expiry'] = T.nullable(T.string({ max=512 })),
    wpwatchdefault = T.nullable(T.string({ max=8 })),
    ['wpwatchdefault-expiry'] = T.nullable(T.string({ max=512 })),
    wpwatchdeletion = T.nullable(T.string({ max=8 })),
    wpwatchlistdays = T.nullable(T.number_query({ integer=true })),
    wpwatchlisthideanons = T.nullable(T.string({ max=8 })),
    wpwatchlisthidebots = T.nullable(T.string({ max=8 })),
    wpwatchlisthidecategorization = T.nullable(T.string({ max=8 })),
    wpwatchlisthideliu = T.nullable(T.string({ max=8 })),
    wpwatchlisthideminor = T.nullable(T.string({ max=8 })),
    wpwatchlisthideown = T.nullable(T.string({ max=8 })),
    wpwatchlisthidepatrolled = T.nullable(T.string({ max=8 })),
    wpwatchlistlabelonboarding = T.nullable(T.string({ max=512 })),
    wpwatchlistreloadautomatically = T.nullable(T.string({ max=8 })),
    wpwatchlisttoken = T.nullable(T.string({ max=512 })),
    ['wpwatchlisttoken-info'] = T.nullable(T.string({ max=512 })),
    wpwatchlistunwatchlinks = T.nullable(T.string({ max=8 })),
    wpwatchmoves = T.nullable(T.string({ max=8 })),
    wpwatchrollback = T.nullable(T.string({ max=8 })),
    ['wpwatchrollback-expiry'] = T.nullable(T.string({ max=512 })),
    wpwatchuploads = T.nullable(T.string({ max=8 })),
    ['wpwlenhancedfilters-disable'] = T.nullable(T.string({ max=8 })),
    wpwllimit = T.nullable(T.number_query({ integer=true })),
  }),
  -- Prefixindex
  T.object({
    from = T.nullable(T.string({ max=512 })),
    hideredirects = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    prefix = T.nullable(T.string({ max=512 })),
    stripprefix = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    to = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Protectedpages
  T.object({
    level = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    size = T.nullable(T.string({ max=512 })),
    ['size-mode'] = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    type = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpfilters = T.nullable(T.string({ max=512 })),
  }),
  -- Protectedtitles
  T.object({
    level = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- RandomInCategory
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpcategory = T.nullable(T.string({ max=512 })),
  }),
  -- Randompage
  T.object({
    action = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Recentchanges
  T.object({
    action = T.nullable(T.string({ max=512 })),
    enable_partitioning = T.nullable(T.string({ max=512 })),
    feed = T.nullable(T.string({ max=512 })),
    peek = T.nullable(T.string({ max=512 })),
    rcfilters = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    urlversion = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Recentchangeslinked
  T.object({
    action = T.nullable(T.string({ max=512 })),
    enable_partitioning = T.nullable(T.string({ max=512 })),
    feed = T.nullable(T.string({ max=512 })),
    peek = T.nullable(T.string({ max=512 })),
    rcfilters = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    urlversion = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Redirect
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wptype = T.nullable(T.string({ max=8, enum={ ['user']=true, ['page']=true, ['revision']=true, ['file']=true, ['logid']=true } })),
    wpvalue = T.nullable(T.string({ max=512 })),
  }),
  -- RemoveCredentials
  T.object({
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Renameuser
  T.object({
    confirmaction = T.nullable(T.string({ max=512 })),
    forceglobaldetach = T.nullable(T.string({ max=512 })),
    movepages = T.nullable(T.string({ max=512 })),
    newusername = T.nullable(T.string({ max=512 })),
    oldusername = T.nullable(T.string({ max=512 })),
    reason = T.nullable(T.string({ max=1024 })),
    suppressredirect = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- ResetTokens
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wptokens = T.nullable(T.string({ max=512 })),
  }),
  -- Revisiondelete
  T.object({
    file = T.nullable(T.string({ max=512 })),
    ids = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
    type = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpHideComment = T.nullable(T.string({ max=1024 })),
    wpHidePrimary = T.nullable(T.string({ max=512 })),
    wpHideRestricted = T.nullable(T.string({ max=512 })),
    wpHideUser = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpReasonDropDown = T.nullable(T.string({ max=1024 })),
    wpRevDeleteReasonList = T.nullable(T.string({ max=1024 })),
    wpSubmit = T.nullable(T.string({ max=512 })),
  }),
  -- Tags
  T.object({
    tag = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- TalkPage
  T.object({
    target = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Unblock
  T.object({
    ip = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    usecodex = T.nullable(T.string({ max=512 })),
    wpBlockAddress = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpTarget = T.nullable(T.string({ max=512 })),
  }),
  -- Undelete
  T.object({
    action = T.nullable(T.string({ max=512 })),
    diff = T.nullable(T.string({ max=512 })),
    diffonly = T.nullable(T.string({ max=512 })),
    file = T.nullable(T.string({ max=512 })),
    fuzzy = T.nullable(T.string({ max=512 })),
    historyoffset = T.nullable(T.string({ max=512 })),
    invert = T.nullable(T.string({ max=512 })),
    prefix = T.nullable(T.string({ max=512 })),
    preview = T.nullable(T.string({ max=512 })),
    restore = T.nullable(T.string({ max=512 })),
    revdel = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    timestamp = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
    undeletetalk = T.nullable(T.string({ max=512 })),
    wpComment = T.nullable(T.string({ max=1024 })),
    wpCommentList = T.nullable(T.string({ max=1024 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpUnsuppress = T.nullable(T.string({ max=512 })),
    wpWatch = T.nullable(T.string({ max=512 })),
  }),
  -- UnlinkAccounts
  T.object({
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Unlockdb
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpConfirm = T.nullable(T.string({ max=8 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Upload
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wpCacheKey = T.nullable(T.string({ max=512 })),
    wpCancelUpload = T.nullable(T.string({ max=512 })),
    wpChangeTags = T.nullable(T.string({ max=512 })),
    wpDestFile = T.nullable(T.string({ max=512 })),
    wpDestFileWarningAck = T.nullable(T.string({ max=512 })),
    wpDestUrl = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpForReUpload = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpIgnoreWarning = T.nullable(T.string({ max=512 })),
    wpLicense = T.nullable(T.string({ max=512 })),
    wpReUpload = T.nullable(T.string({ max=512 })),
    wpSourceType = T.nullable(T.string({ max=512 })),
    wpUpload = T.nullable(T.string({ max=512 })),
    wpUploadCopyStatus = T.nullable(T.string({ max=512 })),
    wpUploadDescription = T.nullable(T.string({ max=65536 })),
    wpUploadFile = T.nullable(T.string({ max=512 })),
    wpUploadIgnoreWarning = T.nullable(T.string({ max=512 })),
    wpUploadSource = T.nullable(T.string({ max=512 })),
    wpWatchthis = T.nullable(T.string({ max=512 })),
  }),
  -- Userlogin
  T.object({
    action = T.nullable(T.string({ max=512 })),
    alwaysShowLogin = T.nullable(T.string({ max=512 })),
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    error = T.nullable(T.string({ max=512 })),
    force = T.nullable(T.string({ max=512 })),
    fromhttp = T.nullable(T.string({ max=512 })),
    notice = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    type = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    warning = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
    wpCreateaccount = T.nullable(T.string({ max=512 })),
    wpCreateaccountMail = T.nullable(T.string({ max=512 })),
    wpCreateaccountToken = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpEmail = T.nullable(T.string({ max=512 })),
    wpForceHttps = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpFromhttp = T.nullable(T.string({ max=512 })),
    wpLoginToken = T.nullable(T.string({ max=512 })),
    wpName = T.nullable(T.string({ max=512 })),
    wpName1 = T.nullable(T.string({ max=512 })),
    wpName2 = T.nullable(T.string({ max=512 })),
    wpPassword = T.nullable(T.string({ max=512 })),
    wpPassword1 = T.nullable(T.string({ max=512 })),
    wpPassword2 = T.nullable(T.string({ max=512 })),
    wpRealName = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpRemember = T.nullable(T.string({ max=512 })),
    wpRetype = T.nullable(T.string({ max=512 })),
    wploginattempt = T.nullable(T.string({ max=512 })),
  }),
  -- Userlogout
  T.object({
    title = T.nullable(T.string({ max=512 })),
    wasTempUser = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Userrights
  T.object({
    saveusergroups = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    user = T.nullable(T.string({ max=512 })),
    ['user-reason'] = T.nullable(T.string({ max=1024 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpWatch = T.nullable(T.string({ max=512 })),
  }),
  -- Watchlist
  T.object({
    action = T.nullable(T.string({ max=512 })),
    enable_partitioning = T.nullable(T.string({ max=512 })),
    peek = T.nullable(T.string({ max=512 })),
    rcfilters = T.nullable(T.string({ max=512 })),
    reset = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
    urlversion = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- WatchlistLabels
  T.object({
    asc = T.nullable(T.string({ max=512 })),
    sort = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
  -- Whatlinkshere
  T.object({
    dir = T.nullable(T.string({ max=512 })),
    from = T.nullable(T.string({ max=512 })),
    invert = T.nullable(T.string({ max=8 })),
    limit = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    offset = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFormIdentifier = T.nullable(T.string({ max=512 })),
  }),
}

-- Reassigns the forward-declared local from earlier in this file (NOT
-- `local` here - see the comment next to its declaration, right after
-- mw_special_pages, for why). Same {label, titles, fields} shape as
-- mw_special_pages, covering the query-string ?title=Special:X form for
-- every page below that ISN'T one of the 16 already hand-tuned there.
mw_bulk_special_query_pages = {
  { label = 'apihelp', titles = { 'Special:ApiHelp' }, fields = {
    recursivesubmodules = T.nullable(T.string({ max=512 })),
    submodules = T.nullable(T.string({ max=512 })),
    title = T.nullable(T.string({ max=512 })),
  } },
  { label = 'authenticationpopupsuccess', titles = { 'Special:AuthenticationPopupSuccess' }, fields = {
    display = T.nullable(T.string({ max=512 })),
  } },
  { label = 'blocklist', titles = { 'Special:BlockList' }, fields = {
    action = T.nullable(T.string({ max=512 })),
    blockType = T.nullable(T.string({ max=512 })),
    ip = T.nullable(T.string({ max=512 })),
    wpOptions = T.nullable(T.string({ max=512 })),
    wpTarget = T.nullable(T.string({ max=512 })),
  } },
  { label = 'booksources', titles = { 'Special:Booksources' }, fields = {
    isbn = T.nullable(T.string({ max=512 })),
  } },
  { label = 'categories', titles = { 'Special:Categories' }, fields = {
    from = T.nullable(T.string({ max=512 })),
  } },
  { label = 'changecredentials', titles = { 'Special:ChangeCredentials' }, fields = {
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    password = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    retype = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
    wpusername = T.nullable(T.string({ max=512 })),
  } },
  { label = 'changepassword', titles = { 'Special:ChangePassword' }, fields = {
    returnto = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
  } },
  { label = 'createaccount', titles = { 'Special:CreateAccount' }, fields = {
    action = T.nullable(T.string({ max=512 })),
    alwaysShowLogin = T.nullable(T.string({ max=512 })),
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    error = T.nullable(T.string({ max=512 })),
    force = T.nullable(T.string({ max=512 })),
    fromhttp = T.nullable(T.string({ max=512 })),
    notice = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    warning = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
    wpCreateaccount = T.nullable(T.string({ max=512 })),
    wpCreateaccountMail = T.nullable(T.string({ max=512 })),
    wpCreateaccountToken = T.nullable(T.string({ max=512 })),
    wpEmail = T.nullable(T.string({ max=512 })),
    wpForceHttps = T.nullable(T.string({ max=512 })),
    wpFromhttp = T.nullable(T.string({ max=512 })),
    wpLoginToken = T.nullable(T.string({ max=512 })),
    wpName = T.nullable(T.string({ max=512 })),
    wpName1 = T.nullable(T.string({ max=512 })),
    wpName2 = T.nullable(T.string({ max=512 })),
    wpPassword = T.nullable(T.string({ max=512 })),
    wpPassword1 = T.nullable(T.string({ max=512 })),
    wpPassword2 = T.nullable(T.string({ max=512 })),
    wpRealName = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpRemember = T.nullable(T.string({ max=512 })),
    wpRetype = T.nullable(T.string({ max=512 })),
    wploginattempt = T.nullable(T.string({ max=512 })),
  } },
  { label = 'deletedcontributions', titles = { 'Special:DeletedContributions' }, fields = {
    associated = T.nullable(T.string({ max=512 })),
    bot = T.nullable(T.string({ max=512 })),
    deletedOnly = T.nullable(T.string({ max=512 })),
    ['end'] = T.nullable(T.string({ max=512 })),
    feed = T.nullable(T.string({ max=512 })),
    hideMinor = T.nullable(T.string({ max=512 })),
    limit = T.nullable(T.string({ max=512 })),
    month = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    newOnly = T.nullable(T.string({ max=512 })),
    nsInvert = T.nullable(T.string({ max=512 })),
    start = T.nullable(T.string({ max=512 })),
    tagInvert = T.nullable(T.string({ max=512 })),
    tagfilter = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    topOnly = T.nullable(T.string({ max=512 })),
    wpfilters = T.nullable(T.string({ max=512 })),
    year = T.nullable(T.string({ max=512 })),
  } },
  { label = 'edittags', titles = { 'Special:EditTags' }, fields = {
    ids = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    type = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpExistingTags = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpRemoveAllTags = T.nullable(T.string({ max=512 })),
    wpSubmit = T.nullable(T.string({ max=512 })),
    wpTagList = T.nullable(T.string({ max=512 })),
    wpTagsToRemove = T.nullable(T.string({ max=512 })),
    wpfilters = T.nullable(T.string({ max=512 })),
  } },
  { label = 'editwatchlist', titles = { 'Special:EditWatchlist' }, fields = {
    action = T.nullable(T.string({ max=512 })),
    limit = T.nullable(T.string({ max=512 })),
    watchlistlabels = T.nullable(T.string({ max=512 })),
    ['watchlistlabels-action'] = T.nullable(T.string({ max=512 })),
    wpTitles = T.nullable(T.string({ max=512 })),
  } },
  { label = 'expandtemplates', titles = { 'Special:ExpandTemplates' }, fields = {
    wpContextTitle = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpGenerateRawHtml = T.nullable(T.string({ max=512 })),
    wpGenerateXml = T.nullable(T.string({ max=512 })),
    wpInput = T.nullable(T.string({ max=512 })),
    wpRemoveComments = T.nullable(T.string({ max=512 })),
    wpRemoveNowiki = T.nullable(T.string({ max=512 })),
  } },
  { label = 'export', titles = { 'Special:Export' }, fields = {
    addcat = T.nullable(T.string({ max=512 })),
    addns = T.nullable(T.string({ max=512 })),
    catname = T.nullable(T.string({ max=512 })),
    curonly = T.nullable(T.string({ max=512 })),
    dir = T.nullable(T.string({ max=512 })),
    exportall = T.nullable(T.string({ max=512 })),
    history = T.nullable(T.string({ max=512 })),
    limit = T.nullable(T.string({ max=512 })),
    listauthors = T.nullable(T.string({ max=512 })),
    nsindex = T.nullable(T.string({ max=512 })),
    offset = T.nullable(T.string({ max=512 })),
    ['pagelink-depth'] = T.nullable(T.string({ max=512 })),
    pages = T.nullable(T.string({ max=512 })),
    templates = T.nullable(T.string({ max=512 })),
    wpDownload = T.nullable(T.string({ max=512 })),
    wpExportTemplates = T.nullable(T.string({ max=512 })),
  } },
  { label = 'fileduplicatesearch', titles = { 'Special:FileDuplicateSearch' }, fields = {
    filename = T.nullable(T.string({ max=512 })),
  } },
  { label = 'import', titles = { 'Special:Import' }, fields = {
    action = T.nullable(T.string({ max=512 })),
    assignKnownUsers = T.nullable(T.string({ max=512 })),
    frompage = T.nullable(T.string({ max=512 })),
    interwiki = T.nullable(T.string({ max=512 })),
    interwikiHistory = T.nullable(T.string({ max=512 })),
    interwikiTemplates = T.nullable(T.string({ max=512 })),
    ['log-comment'] = T.nullable(T.string({ max=1024 })),
    mapping = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    ['pagelink-depth'] = T.nullable(T.string({ max=512 })),
    rootpage = T.nullable(T.string({ max=512 })),
    source = T.nullable(T.string({ max=512 })),
    subproject = T.nullable(T.string({ max=512 })),
    usernamePrefix = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
  } },
  { label = 'interwiki', titles = { 'Special:Interwiki' }, fields = {
    action = T.nullable(T.string({ max=512 })),
    prefix = T.nullable(T.string({ max=512 })),
  } },
  { label = 'linkaccounts', titles = { 'Special:LinkAccounts' }, fields = {
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
  } },
  { label = 'listfiles', titles = { 'Special:Listfiles' }, fields = {
    ilsearch = T.nullable(T.string({ max=512 })),
    ilshowall = T.nullable(T.string({ max=512 })),
    user = T.nullable(T.string({ max=512 })),
  } },
  { label = 'movepage', titles = { 'Special:Movepage' }, fields = {
    action = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    wpDeleteAndMove = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpFixRedirects = T.nullable(T.string({ max=512 })),
    wpLeaveRedirect = T.nullable(T.string({ max=512 })),
    wpMove = T.nullable(T.string({ max=512 })),
    wpMoveOverProtection = T.nullable(T.string({ max=512 })),
    wpMoveOverSharedFile = T.nullable(T.string({ max=512 })),
    wpMovesubpages = T.nullable(T.string({ max=512 })),
    wpMovetalk = T.nullable(T.string({ max=512 })),
    ['wpMovetalk-field'] = T.nullable(T.string({ max=512 })),
    wpNewTitle = T.nullable(T.string({ max=512 })),
    wpNewTitleMain = T.nullable(T.string({ max=512 })),
    wpNewTitleNs = T.nullable(T.string({ max=512 })),
    wpOldTitle = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpReasonList = T.nullable(T.string({ max=1024 })),
    wpWatch = T.nullable(T.string({ max=512 })),
    wpWatchlistExpiry = T.nullable(T.string({ max=512 })),
  } },
  { label = 'prefixindex', titles = { 'Special:Prefixindex' }, fields = {
    from = T.nullable(T.string({ max=512 })),
    hideredirects = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    prefix = T.nullable(T.string({ max=512 })),
    stripprefix = T.nullable(T.string({ max=512 })),
    to = T.nullable(T.string({ max=512 })),
  } },
  { label = 'protectedpages', titles = { 'Special:Protectedpages' }, fields = {
    level = T.nullable(T.string({ max=512 })),
    namespace = T.nullable(T.string({ max=512 })),
    size = T.nullable(T.string({ max=512 })),
    ['size-mode'] = T.nullable(T.string({ max=512 })),
    type = T.nullable(T.string({ max=512 })),
    wpfilters = T.nullable(T.string({ max=512 })),
  } },
  { label = 'randompage', titles = { 'Special:Randompage' }, fields = {
    action = T.nullable(T.string({ max=512 })),
  } },
  { label = 'recentchanges', titles = { 'Special:Recentchanges' }, fields = {
    action = T.nullable(T.string({ max=512 })),
    enable_partitioning = T.nullable(T.string({ max=512 })),
    feed = T.nullable(T.string({ max=512 })),
    peek = T.nullable(T.string({ max=512 })),
    rcfilters = T.nullable(T.string({ max=512 })),
    urlversion = T.nullable(T.string({ max=512 })),
  } },
  { label = 'removecredentials', titles = { 'Special:RemoveCredentials' }, fields = {
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
  } },
  { label = 'renameuser', titles = { 'Special:Renameuser' }, fields = {
    confirmaction = T.nullable(T.string({ max=512 })),
    forceglobaldetach = T.nullable(T.string({ max=512 })),
    movepages = T.nullable(T.string({ max=512 })),
    newusername = T.nullable(T.string({ max=512 })),
    oldusername = T.nullable(T.string({ max=512 })),
    reason = T.nullable(T.string({ max=1024 })),
    suppressredirect = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
  } },
  { label = 'revisiondelete', titles = { 'Special:Revisiondelete' }, fields = {
    file = T.nullable(T.string({ max=512 })),
    ids = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
    type = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpHideComment = T.nullable(T.string({ max=1024 })),
    wpHidePrimary = T.nullable(T.string({ max=512 })),
    wpHideRestricted = T.nullable(T.string({ max=512 })),
    wpHideUser = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpReasonDropDown = T.nullable(T.string({ max=1024 })),
    wpRevDeleteReasonList = T.nullable(T.string({ max=1024 })),
    wpSubmit = T.nullable(T.string({ max=512 })),
  } },
  { label = 'tags', titles = { 'Special:Tags' }, fields = {
    tag = T.nullable(T.string({ max=512 })),
  } },
  { label = 'unblock', titles = { 'Special:Unblock' }, fields = {
    ip = T.nullable(T.string({ max=512 })),
    usecodex = T.nullable(T.string({ max=512 })),
    wpBlockAddress = T.nullable(T.string({ max=512 })),
    wpTarget = T.nullable(T.string({ max=512 })),
  } },
  { label = 'undelete', titles = { 'Special:Undelete' }, fields = {
    action = T.nullable(T.string({ max=512 })),
    diff = T.nullable(T.string({ max=512 })),
    diffonly = T.nullable(T.string({ max=512 })),
    file = T.nullable(T.string({ max=512 })),
    fuzzy = T.nullable(T.string({ max=512 })),
    historyoffset = T.nullable(T.string({ max=512 })),
    invert = T.nullable(T.string({ max=512 })),
    prefix = T.nullable(T.string({ max=512 })),
    preview = T.nullable(T.string({ max=512 })),
    restore = T.nullable(T.string({ max=512 })),
    revdel = T.nullable(T.string({ max=512 })),
    target = T.nullable(T.string({ max=512 })),
    timestamp = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
    undeletetalk = T.nullable(T.string({ max=512 })),
    wpComment = T.nullable(T.string({ max=1024 })),
    wpCommentList = T.nullable(T.string({ max=1024 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpUnsuppress = T.nullable(T.string({ max=512 })),
    wpWatch = T.nullable(T.string({ max=512 })),
  } },
  { label = 'unlinkaccounts', titles = { 'Special:UnlinkAccounts' }, fields = {
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
  } },
  { label = 'upload', titles = { 'Special:Upload' }, fields = {
    wpCacheKey = T.nullable(T.string({ max=512 })),
    wpCancelUpload = T.nullable(T.string({ max=512 })),
    wpChangeTags = T.nullable(T.string({ max=512 })),
    wpDestFile = T.nullable(T.string({ max=512 })),
    wpDestFileWarningAck = T.nullable(T.string({ max=512 })),
    wpDestUrl = T.nullable(T.string({ max=512 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpForReUpload = T.nullable(T.string({ max=512 })),
    wpIgnoreWarning = T.nullable(T.string({ max=512 })),
    wpLicense = T.nullable(T.string({ max=512 })),
    wpReUpload = T.nullable(T.string({ max=512 })),
    wpSourceType = T.nullable(T.string({ max=512 })),
    wpUpload = T.nullable(T.string({ max=512 })),
    wpUploadCopyStatus = T.nullable(T.string({ max=512 })),
    wpUploadDescription = T.nullable(T.string({ max=65536 })),
    wpUploadFile = T.nullable(T.string({ max=512 })),
    wpUploadIgnoreWarning = T.nullable(T.string({ max=512 })),
    wpUploadSource = T.nullable(T.string({ max=512 })),
    wpWatchthis = T.nullable(T.string({ max=512 })),
  } },
  { label = 'userlogin', titles = { 'Special:Userlogin' }, fields = {
    action = T.nullable(T.string({ max=512 })),
    alwaysShowLogin = T.nullable(T.string({ max=512 })),
    authAction = T.nullable(T.string({ max=512 })),
    authUniqueId = T.nullable(T.string({ max=512 })),
    error = T.nullable(T.string({ max=512 })),
    force = T.nullable(T.string({ max=512 })),
    fromhttp = T.nullable(T.string({ max=512 })),
    notice = T.nullable(T.string({ max=512 })),
    returnto = T.nullable(T.string({ max=512 })),
    returntoanchor = T.nullable(T.string({ max=512 })),
    returntoquery = T.nullable(T.string({ max=512 })),
    type = T.nullable(T.string({ max=512 })),
    uselang = T.nullable(T.string({ max=512 })),
    variant = T.nullable(T.string({ max=512 })),
    warning = T.nullable(T.string({ max=512 })),
    wpAuthToken = T.nullable(T.string({ max=512 })),
    wpCreateaccount = T.nullable(T.string({ max=512 })),
    wpCreateaccountMail = T.nullable(T.string({ max=512 })),
    wpCreateaccountToken = T.nullable(T.string({ max=512 })),
    wpEmail = T.nullable(T.string({ max=512 })),
    wpForceHttps = T.nullable(T.string({ max=512 })),
    wpFromhttp = T.nullable(T.string({ max=512 })),
    wpLoginToken = T.nullable(T.string({ max=512 })),
    wpName = T.nullable(T.string({ max=512 })),
    wpName1 = T.nullable(T.string({ max=512 })),
    wpName2 = T.nullable(T.string({ max=512 })),
    wpPassword = T.nullable(T.string({ max=512 })),
    wpPassword1 = T.nullable(T.string({ max=512 })),
    wpPassword2 = T.nullable(T.string({ max=512 })),
    wpRealName = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpRemember = T.nullable(T.string({ max=512 })),
    wpRetype = T.nullable(T.string({ max=512 })),
    wploginattempt = T.nullable(T.string({ max=512 })),
  } },
  { label = 'userlogout', titles = { 'Special:Userlogout' }, fields = {
    wasTempUser = T.nullable(T.string({ max=512 })),
  } },
  { label = 'userrights', titles = { 'Special:Userrights' }, fields = {
    saveusergroups = T.nullable(T.string({ max=512 })),
    user = T.nullable(T.string({ max=512 })),
    ['user-reason'] = T.nullable(T.string({ max=1024 })),
    wpEditToken = T.nullable(T.string({ max=512 })),
    wpReason = T.nullable(T.string({ max=1024 })),
    wpWatch = T.nullable(T.string({ max=512 })),
  } },
  { label = 'watchlist', titles = { 'Special:Watchlist' }, fields = {
    action = T.nullable(T.string({ max=512 })),
    enable_partitioning = T.nullable(T.string({ max=512 })),
    peek = T.nullable(T.string({ max=512 })),
    rcfilters = T.nullable(T.string({ max=512 })),
    reset = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
    urlversion = T.nullable(T.string({ max=512 })),
  } },
  { label = 'watchlistlabels', titles = { 'Special:WatchlistLabels' }, fields = {
    asc = T.nullable(T.string({ max=512 })),
    sort = T.nullable(T.string({ max=512 })),
  } },
}

-- ---------------------------------------------------------------------------
-- load.php GET query schema
-- ---------------------------------------------------------------------------
local load_get_query = T.object({
  lang            = T.string({ max=16 }),
  modules         = T.string({ max=4096 }),
  only            = T.string({ max=16 }),
  skin            = T.string({ max=32 }),
  raw             = T.string({ max=4 }),
  vector          = T.string({ max=64 }),
  format          = T.string({ max=16 }),
  image           = T.string({ max=64 }),
  oldid           = T.string({ max=20 }),
  version         = T.string({ max=32 }),
  variant         = T.string({ max=16 }),
  sourcemap       = T.string({ max=4 }),
  safemode        = T.string({ max=4 }),
})

-- Built here, not back where mw_special_pages/index_query_check/
-- each_special_query_page are defined, because it depends on
-- mw_bulk_special_query_pages, which only gets reassigned its real content
-- inside the generated Tier 6 block further up - T.object() bakes in
-- whatever key set its schema table holds AT THE MOMENT IT'S CALLED (unlike
-- index_query_check, a plain function whose body only runs later, at
-- request-validation time, long after the whole module including that
-- reassignment has finished loading). Also deliberately placed AFTER the
-- "load.php GET query schema" marker above (not just after the
-- reassignment), not before it: integrate_all_special_pages.py wholesale-
-- replaces everything from its own block header through right up to that
-- marker on every regen - anything placed inside that span, even textually
-- after the reassignment, gets silently deleted on the next run (confirmed
-- the hard way: index_query ended up nil, silently disabling query
-- validation on "index php get" entirely - not caught by the test suite
-- either, since a nil route.query just makes the query-invalid test
-- section skip itself rather than fail).
local mw_special_fields = {}
each_special_query_page(function(page)
  mw_special_fields = merge(mw_special_fields, page.fields)
end)

local index_query = T.with_check(
  T.object(merge(idx_common, mw_special_fields)),
  index_query_check
)

local mw_routes = (function()
  local rs = {

    -------------------------------------------------------------------------
    -- Root and simple pages
    -------------------------------------------------------------------------
    { name="root",    method="GET", path=[[^/$]],             no_query=true, no_body=true },
    { name="favicon", method="GET", path=[[^/favicon\.ico$]], no_query=true, no_body=true },

    -------------------------------------------------------------------------
    -- Static assets (GET only, restricted by extension)
    -------------------------------------------------------------------------
    {
      name    = "resources",
      method  = "GET",
      paths   = {
        [[^/resources/.*\.(jpeg|jpg|png|gif|webp|svg)$]],
        [[^/images/.*\.(jpeg|jpg|png|gif|webp|svg)$]],
      },
      no_body = true,
    },
    {
      name    = "skins",
      method  = "GET",
      path    = [[^/skins/.*\.(jpg|png|gif|webp|svg)$]],
      no_body = true,
    },

    -------------------------------------------------------------------------
    -- rest.php  (MediaWiki REST API v1)
    -- Accepts: GET /rest.php and GET /rest.php/v1/search/title[?q=...]
    -------------------------------------------------------------------------
    {
      name    = "rest php",
      method  = "GET",
      paths   = {
        [[^/rest\.php$]],
        [[^/rest\.php/v1/search/title]],
      },
      no_body = true,
    },

    -------------------------------------------------------------------------
    -- api.php GET  (Action API — read operations, opensearch, etc.)
    -------------------------------------------------------------------------
    {
      name    = "api get",
      method  = "GET",
      path    = [[^/api\.php$]],
      query   = api_schema,
      no_body = true,
    },

    -------------------------------------------------------------------------
    -- api.php POST  (Action API — edit, token, module operations)
    -------------------------------------------------------------------------
    {
      name         = "api post",
      method       = "POST",
      path         = [[^/api\.php$]],
      content_type = "application/x-www-form-urlencoded",
      form         = api_schema,
    },

    -------------------------------------------------------------------------
    -- index.php  (all standard page views and form submissions)
    -- Handles /index.php and /index.php/Article_Title style paths.
    --
    -- Routes are listed most-specific-first: each Special: page used via the
    -- clean-path form (/index.php/Special:Foo) gets its own route with its
    -- own extra-params schema, so the generic catch-all below never shadows
    -- them. The same pages accessed via ?title=Special:Foo are handled by
    -- index_query's title-gated cross-check instead, since routing can only
    -- see the URI path, not the query string.
    -------------------------------------------------------------------------
    special_page_route("allpages",            "Special:AllPages",            page_fields("allpages")),
    special_page_route("listusers",           "Special:ListUsers",           page_fields("listusers")),
    special_page_route("recentchangeslinked", "Special:RecentChangesLinked", page_fields("recentchangeslinked", "shared_target")),
    special_page_route("redirect",            "Special:Redirect",            page_fields("redirect")),
    special_page_route("protectedtitles",     "Special:ProtectedTitles",     page_fields("protectedtitles")),
    special_page_route("log",                 "Special:Log",                 page_fields("log")),
    special_page_route("activeusers",         "Special:ActiveUsers",         page_fields("activeusers")),
    special_page_route("comparepages",        "Special:ComparePages",        page_fields("comparepages")),
    special_page_route("linksearch",          "Special:LinkSearch",          page_fields("shared_target")),
    special_page_route("whatlinkshere",       "Special:WhatLinksHere",       page_fields("whatlinkshere", "shared_target")),
    special_page_route("mimesearch",          "Special:MIMESearch",          page_fields("mimesearch")),
    special_page_route("newpages",            "Special:NewPages",            page_fields("newpages")),
    special_page_route("mergehistory",        "Special:MergeHistory",        page_fields("mergehistory", "shared_target")),
    special_page_route("pageswithprop",       "Special:PagesWithProp",       page_fields("pageswithprop")),
    special_page_route("contributions",       "Special:Contributions",       page_fields("contributions")),
    allmessages_route,
  }
  for _, r in ipairs(mw_bulk_special_routes) do rs[#rs + 1] = r end
  for _, r in ipairs({
    {
      name    = "index php get",
      method  = "GET",
      paths   = {
        [[^/index\.php$]],
        [[^/index\.php/]],
      },
      query   = index_query,
      no_body = true,
    },
    {
      name    = "index php post",
      method  = "POST",
      paths   = {
        [[^/index\.php$]],
        [[^/index\.php/]],
      },
      -- MediaWiki edit submissions use multipart/form-data
      content_types = {
        "application/x-www-form-urlencoded",
        "multipart/form-data",
      },
      query = index_query,
      form_schemas = (function()
        local fs = { index_post_form }
        for _, f in ipairs(mw_index_action_forms) do fs[#fs + 1] = f end
        for _, f in ipairs(mw_special_post_forms) do fs[#fs + 1] = f end
        return fs
      end)(),
    },

    -------------------------------------------------------------------------
    -- load.php  (ResourceLoader — JS/CSS module delivery)
    -------------------------------------------------------------------------
    {
      name    = "load php get",
      method  = "GET",
      path    = [[^/load\.php$]],
      query   = load_get_query,
      no_body = true,
    },
    {
      name    = "load php post",
      method  = "POST",
      path    = [[^/load\.php$]],
      form    = T.object({ oldid = T.string({ max=20 }) }),
    },

    }) do rs[#rs + 1] = r end
  return rs
end)()

-- ---------------------------------------------------------------------------

return {
  name = "mediawiki",
  mode = "log",   -- switch to "block" after validating against real traffic

  defaults = {
    max_body        = 4 * 1024 * 1024,
    allowed_methods = { GET=true, POST=true, OPTIONS=true },
    allowed_headers = T.merge_headers(T.common_request_headers(), _mw_extra_headers),
    headers = {
      -- MediaWiki is accessed by browsers, bots, and API clients.
      -- T.string({ max=512 }) permits any reasonable UA string.
      -- To restrict to browsers only, use:
      -- ["User-Agent"] = T.string({ max=512, match=[[Mozilla/5\.0]] }),
      ["User-Agent"] = T.string({ max=512 }),
      ["priority"]   = T.http_priority(),
      ["sec-gpc"]    = T.sec_gpc(),
    },
  },

  routes = mw_routes,
}
