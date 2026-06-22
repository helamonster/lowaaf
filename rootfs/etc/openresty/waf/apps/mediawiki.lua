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
  "sec-gpc",
  "priority",
  "amp-cache-transform",
  "from",
}

-- ---------------------------------------------------------------------------
-- index.php query parameter schema
--
-- MediaWiki routes nearly all page requests through index.php with a large
-- set of optional query parameters. Rather than enumerating per-page subsets
-- (as the original PoC did), we declare the full union of known-good params
-- once. The key security property is that UNKNOWN params are rejected.
-- Per-param value constraints are added where the PoC explicitly validated
-- them (filter, size).
-- ---------------------------------------------------------------------------

local idx_base = {
  -- navigation / page identity
  title           = T.string({ max=512 }),
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

  -- array-style params (MediaWiki passes these as key[])
  ["wpOptions[]"] = T.string({ max=64 }),
  ["wpfilters[]"] = T.string({ max=64 }),

  -- Special:AllPages
  to              = T.string({ max=512 }),
  hideredirects   = T.string({ max=4 }),

  -- Special:ListUsers
  creationSort    = T.string({ max=8 }),
  desc            = T.string({ max=8 }),

  -- Special:RecentChangesLinked
  showlinkedto    = T.string({ max=4 }),
  target          = T.string({ max=512 }),

  -- Special:LinkSearch
  -- (target, namespace already declared above)

  -- Special:Redirect
  wptype          = T.string({ max=32 }),
  wpvalue         = T.string({ max=512 }),

  -- Special:ProtectedTitles
  level           = T.string({ max=8 }),

  -- Special:Log
  logid           = T.string({ max=20 }),
  pattern         = T.string({ max=256 }),
  tagInvert       = T.string({ max=4 }),
  subtype         = T.string({ max=64 }),

  -- Special:NewPages
  ["size-mode"]   = T.string({ max=8 }),
  size            = T.number({ integer=true, min=0, max=17592186044416 }),
  associated      = T.string({ max=4 }),
  invert          = T.string({ max=4 }),
  hideliu         = T.string({ max=4 }),
  hideredirs      = T.string({ max=4 }),
  hidepatrolled   = T.string({ max=4 }),
  hideMinor       = T.string({ max=4 }),
  newOnly         = T.string({ max=4 }),
  topOnly         = T.string({ max=4 }),
  ["wpfilters[]"] = T.string({ max=64 }),

  -- Special:ActiveUsers
  ["groups[]"]    = T.string({ max=64 }),
  ["excludegroups[]"] = T.string({ max=64 }),

  -- Special:AllMessages
  -- filter validated as enum below
  filter          = T.string({ max=16, enum={ unmodified=true, all=true, modified=true } }),

  -- Special:ComparePages / WhatLinksHere / MergeHistory
  rev1            = T.string({ max=20 }),
  rev2            = T.string({ max=20 }),
  unhide          = T.string({ max=4 }),
  page1           = T.string({ max=512 }),
  page2           = T.string({ max=512 }),
  hidetrans       = T.string({ max=4 }),
  hidelinks       = T.string({ max=4 }),
  hideredirs      = T.string({ max=4 }),
  dest            = T.string({ max=512 }),
  submitted       = T.string({ max=4 }),
  mergepoint      = T.string({ max=32 }),

  -- Special:PagesWithProp
  propname        = T.string({ max=64 }),
  reverse         = T.string({ max=4 }),
  sortbyvalue     = T.string({ max=4 }),

  -- Special:Contributions
  start           = T.string({ max=32 }),
  ["end"]         = T.string({ max=32 }),

  -- Special:MIMESearch
  mime            = T.string({ max=64 }),

  -- allusers API context (auexcludetemp)
  auexcludetemp   = T.string({ max=4 }),
}

local index_query = T.object(idx_base)

-- ---------------------------------------------------------------------------
-- api.php GET query schema
-- ---------------------------------------------------------------------------
local api_get_query = T.object({
  action          = T.string({ max=64 }),
  format          = T.string({ max=16 }),
  formatversion   = T.string({ max=4 }),
  search          = T.string({ max=512 }),
  namespace       = T.string({ max=64 }),
  limit           = T.string({ max=10 }),
  uiprop          = T.string({ max=256 }),
  meta            = T.string({ max=64 }),
  generator       = T.string({ max=64 }),
  prop            = T.string({ max=256 }),
  redirects       = T.string({ max=8 }),
  gpsnamespace    = T.string({ max=16 }),
  gpssearch       = T.string({ max=512 }),
  gpslimit        = T.string({ max=10 }),
  ppprop          = T.string({ max=64 }),
  aulimit         = T.string({ max=10 }),
  auprefix        = T.string({ max=256 }),
  auexcludetemp   = T.string({ max=4 }),
  list            = T.string({ max=64 }),
  titles          = T.string({ max=512 }),
  pilimit         = T.string({ max=10 }),
  pithumbsize     = T.string({ max=10 }),
})

-- ---------------------------------------------------------------------------
-- api.php POST form schema
-- ---------------------------------------------------------------------------
local api_post_form = T.object({
  action          = T.string({ max=64 }),
  format          = T.string({ max=16 }),
  formatversion   = T.string({ max=4 }),
  change          = T.string({ max=64 }),
  global          = T.string({ max=8 }),
  search          = T.string({ max=512 }),
  title           = T.string({ max=512 }),
  section         = T.string({ max=16 }),
  sectiontitle    = T.string({ max=512 }),
  summary         = T.string({ max=2048 }),
  contentmodel    = T.string({ max=64 }),
  contentformat   = T.string({ max=64 }),
  baserevid       = T.string({ max=20 }),
  text            = T.string({ max=1024 * 1024 }),  -- wiki page content
  iiprop          = T.string({ max=256 }),
  token           = T.string({ max=256 }),
  helpformat      = T.string({ max=16 }),
  modules         = T.string({ max=512 }),
  uselang         = T.string({ max=16 }),
  titles          = T.string({ max=512 }),
})

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
    },
  },

  routes = {

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
      name    = "rest-php",
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
      name    = "api-get",
      method  = "GET",
      path    = [[^/api\.php$]],
      query   = api_get_query,
      no_body = true,
    },

    -------------------------------------------------------------------------
    -- api.php POST  (Action API — edit, token, module operations)
    -------------------------------------------------------------------------
    {
      name         = "api-post",
      method       = "POST",
      path         = [[^/api\.php$]],
      content_type = "application/x-www-form-urlencoded",
      form         = api_post_form,
    },

    -------------------------------------------------------------------------
    -- index.php  (all standard page views and form submissions)
    -- Handles /index.php and /index.php/Article_Title style paths.
    -- A single broad query schema covers all known Special page variants.
    -------------------------------------------------------------------------
    {
      name    = "index-php-get",
      method  = "GET",
      paths   = {
        [[^/index\.php$]],
        [[^/index\.php/]],
      },
      query   = index_query,
      no_body = true,
    },
    {
      name    = "index-php-post",
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
    },

    -------------------------------------------------------------------------
    -- load.php  (ResourceLoader — JS/CSS module delivery)
    -------------------------------------------------------------------------
    {
      name    = "load-php-get",
      method  = "GET",
      path    = [[^/load\.php$]],
      query   = load_get_query,
      no_body = true,
    },
    {
      name    = "load-php-post",
      method  = "POST",
      path    = [[^/load\.php$]],
      form    = T.object({ oldid = T.string({ max=20 }) }),
    },

  },
}
