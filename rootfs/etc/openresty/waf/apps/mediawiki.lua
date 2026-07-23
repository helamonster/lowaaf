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
  -- Remaining getBaseFilterGroupDefinitions() siblings missed by the initial
  -- pass in 26eabae - confirmed against includes/SpecialPage/ChangesListSpecialPage.php
  -- directly (app-sources/mediawiki/server/mediawiki-1.46.0): hideminor/hidemyself live in the
  -- same 'significance'/'authorship' filter groups as hidemajor/hidebyothers
  -- above, hideanons/hideliu/hidepatrolled/hidecategorization round out the
  -- rest of the group set. Confirmed live: ?hidemyself=1 and ?hideminor=1 on
  -- Special:RecentChangesLinked got denied.
  hideminor       = T.string({ max=4 }),
  hidemyself      = T.string({ max=4 }),
  hideanons       = T.string({ max=4 }),
  hideliu         = T.string({ max=4 }),
  hidepatrolled   = T.string({ max=4 }),
  hidecategorization = T.string({ max=4 }),
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

-- Dedicated routes/forms/query-page coverage for all 132 core Special:
-- pages (everything NOT hand-tuned in mw_special_pages above) - generated
-- by gen_special_pages.py, a factory function (not a plain module table)
-- since its GET routes' query schemas need idx_common, which isn't visible
-- inside a separately-required file. A plain require (executed fully before
-- returning, unlike the old text-splicing approach this replaced) means
-- special_pages.query_pages is real, populated data by the time
-- each_special_query_page below is ever actually CALLED - no forward-
-- declare-then-reassign trick needed anymore (a previous version of this
-- file needed exactly that hack, and getting the reassignment's position
-- wrong once silently disabled all query validation on "index php get" -
-- undetected by the offline test suite).
local special_pages = require("waf.apps.mediawiki.special_pages")(idx_common)

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
-- special_pages.query_pages (generated, the remaining ~116) as if they were
-- one table.
local function each_special_query_page(fn)
  for _, page in ipairs(mw_special_pages) do fn(page) end
  for _, page in ipairs(special_pages.query_pages) do fn(page) end
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

local mw_special_fields = {}
each_special_query_page(function(page)
  mw_special_fields = merge(mw_special_fields, page.fields)
end)

local index_query = T.with_check(
  T.object(merge(idx_common, mw_special_fields)),
  index_query_check
)

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

-- mw_api_actions / mw_query_submodules / resolve_query_submodule_fields /
-- mw_api_action_fields_union / mw_query_submodule_fields_union - generated
-- by gen_api_schema.py from live action=paraminfo introspection (see that
-- file's own header for why), not spliced in here.
local api_gen = require "waf.apps.mediawiki.api_schema"
local mw_api_actions = api_gen.mw_api_actions
local mw_query_submodules = api_gen.mw_query_submodules
local resolve_query_submodule_fields = api_gen.resolve_query_submodule_fields
local mw_api_action_fields_union = api_gen.mw_api_action_fields_union
local mw_query_submodule_fields_union = api_gen.mw_query_submodule_fields_union

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

-- Fields real API actions accept in practice that paraminfo's introspection
-- can't see, because they're consumed by shared/legacy code paths outside
-- getAllowedParams() - mirrors idx_common's manual overrides for Special:
-- pages. Confirmed live: ?urlversion=1&action=feedrecentchanges got denied.
-- ApiFeedRecentChanges::execute() forwards only its own extractRequestParams()
-- output into ChangesListSpecialPage via a DerivativeRequest built from that
-- array, so 'urlversion' on the wire is actually inert (MediaWiki silently
-- ignores it) - but real feed-reader traffic sends it anyway, copied from
-- the Special:RecentChanges URL the feed link was generated from.
local api_manual_action_fields = {
  feedrecentchanges = { urlversion = T.nullable(T.string({ max=4 })) },
}

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
    if api_manual_action_fields[v.action] then
      extra_fields = merge(extra_fields, api_manual_action_fields[v.action])
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

-- Flat union of api_manual_action_fields, for the top-level accepted-keys
-- check below (api_check narrows per-action precisely; this only needs to
-- admit the key at all).
local api_manual_fields_union = {}
for _, fields in pairs(api_manual_action_fields) do
  api_manual_fields_union = merge(api_manual_fields_union, fields)
end

-- Shared by both the GET (query string) and POST (form body) routes below -
-- api.php's parameter namespace is the same regardless of HTTP method.
local api_schema = T.with_check(
  T.object(merge(api_common, api_legacy_fields, mw_api_action_fields_union, mw_query_submodule_fields_union, api_manual_fields_union)),
  api_check
)

-- index_post_form (the standard wikitext edit-submission form, EditPage.php)
-- and action_forms (one per index.php action=X POST target) - generated by
-- gen_edit_forms.py into their own module rather than spliced in here; see
-- that file's own header for field-provenance detail.
local edit_forms = require "waf.apps.mediawiki.edit_forms"

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
  for _, r in ipairs(special_pages.routes) do rs[#rs + 1] = r end
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
        local fs = { edit_forms.index_post_form }
        for _, f in ipairs(edit_forms.action_forms) do fs[#fs + 1] = f end
        for _, f in ipairs(special_pages.post_forms) do fs[#fs + 1] = f end
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
  mode = "block",   -- switch to "block" after validating against real traffic
  verbose = 2,

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
