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
-- jellyfin.lua : LOWAAF policy for Jellyfin
--
-- Jellyfin: The Free Software Media System
-- <https://jellyfin.org>
-- <https://github.com/jellyfin/jellyfin>
--
-- --------------------------------------------------------------------------------------

local T = require "waf.types"

-- ---------------------------------------------------------------------------
-- Jellyfin item ID patterns.
-- Jellyfin uses 32-char hex IDs (no dashes) and 36-char UUIDs interchangeably.
-- ---------------------------------------------------------------------------
local HEX32 = "[0-9a-fA-F]{32}"
local UUID  = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
local ID    = "(?:" .. HEX32 .. "|" .. UUID .. ")"

-- Value validator for a Jellyfin ID (userId, parentId, mediaSourceId, ...)
-- appearing in a query/body field, not a path segment. T.uuid() is too
-- strict here: it requires dashes plus RFC4122 version/variant bits, but
-- real requests send the dashless 32-hex .NET Guid.ToString("N") form too
-- (confirmed via a real deny() log: ?userId=feca5a21d9c8418fbb51eade36f83000).
local function jf_id()
  return T.string({ match = "^" .. ID .. "$", max = 36 })
end

-- Session/device/playlist-entry/timer IDs: opaque server-generated tokens,
-- not necessarily GUID-shaped (SessionController/PlaylistsController/
-- LiveTvController all bind these as plain `string`, not `Guid`).
local OPAQUE_ID = "[0-9A-Za-z_.-]+"

-- PlaystateCommand enum (MediaBrowser.Model.Session.PlaystateCommand)
local PLAYSTATE_COMMAND = "(?:Stop|Pause|Unpause|NextTrack|PreviousTrack|Seek|Rewind|FastForward|PlayPause)"

-- PlayCommand enum (MediaBrowser.Model.Session.PlayCommand)
local PLAY_COMMAND_ENUM = { PlayNow=true, PlayNext=true, PlayLast=true, PlayInstantMix=true, PlayShuffle=true }

-- GeneralCommandType enum (MediaBrowser.Model.Session.GeneralCommandType)
local GENERAL_COMMAND_ENUM = {}
for _, v in ipairs({
  "MoveUp","MoveDown","MoveLeft","MoveRight","PageUp","PageDown","PreviousLetter","NextLetter",
  "ToggleOsd","ToggleContextMenu","Select","Back","TakeScreenshot","SendKey","SendString",
  "GoHome","GoToSettings","VolumeUp","VolumeDown","Mute","Unmute","ToggleMute","SetVolume",
  "SetAudioStreamIndex","SetSubtitleStreamIndex","ToggleFullscreen","DisplayContent","GoToSearch",
  "DisplayMessage","SetRepeatMode","ChannelUp","ChannelDown","Guide","ToggleStats",
  "PlayMediaSource","PlayTrailers","SetShuffleQueue","PlayState","PlayNext","ToggleOsdMenu",
  "Play","SetMaxStreamingBitrate","SetPlaybackOrder",
}) do GENERAL_COMMAND_ENUM[v] = true end


local Q = "(?:0(?:\\.\\d{0,3})?|1(?:\\.0{0,3})?)"
local CHARSET = "(?:\\*|[A-Za-z][A-Za-z0-9._-]*)"

local ACCEPT_CHARSET = [[^\s*(?:]] .. CHARSET .. [[)(?:\s*;\s*q=]] .. Q .. [[)?(?:\s*,\s*(?:]] .. CHARSET .. [[)(?:\s*;\s*q=]] .. Q .. [[)?)*\s*$]]

-- use like:
-- ngx.re.match(val, ACCEPT_CHARSET, "jo")


-- ---------------------------------------------------------------------------
-- User-Agent validators
-- ---------------------------------------------------------------------------

-- Web browser (default)
local function ua_browser()
  return T.string({ max = 512, match = [[Mozilla/5\.0]] })
end

-- Any client: browser, mobile app, desktop player, TV, CLI
local function ua_any()
  return T.string({ max = 512 })
end

-- Accept-Charset 
local function accept_charset()
  return T.string({ max = 512, match = ACCEPT_CHARSET })
end

-- ---------------------------------------------------------------------------

return {
  name = "jellyfin",
  mode = "block",   -- switch to "block" after validating against real traffic
  verbose = 2,

  defaults = {
    max_body        = 10 * 1024 * 1024,
    allowed_methods = { GET=true, POST=true, DELETE=true, OPTIONS=true },
    allowed_headers = T.common_request_headers(),
    headers = {
      -- Jellyfin is accessed by many client types; restrict to browser only if
      -- you are certain no mobile/desktop/TV clients connect from outside.
      -- ["User-Agent"] = ua_browser(),
      ["User-Agent"] = ua_any(),
      ["accept-charset"] = accept_charset(),
      ["x-requested-with"] = T.string( { max = 512 } ),
      ["service-worker"] = T.string({ max = 8, enum = { script = true } }),
      -- Icy-MetaData: audio/video clients request ShoutCast-style stream
      -- metadata injection. Header values are always strings, never Lua
      -- numbers (core.lua passes tostring(value) to every validator) - so
      -- this must be T.string with an enum, not T.number.
      ["icy-metadata"] = T.string({ max = 1, enum = { ["0"] = true, ["1"] = true } }),
    },
  },

  routes = {

    -------------------------------------------------------------------------
    -- Root and common
    -------------------------------------------------------------------------
    { name="root",      method="GET",  path=[[^/$]],           no_body=true },
    { name="favicon",   method="GET",  path=[[^/favicon\.ico$]], no_body=true },
    { name="socket",    method="GET",  path=[[^/socket$]],     no_body=true },
    { name="utctime",   method="GET",  path=[[^/GetUTCTime$]], no_body=true },

    -------------------------------------------------------------------------
    -- Web UI (SPA + static assets)
    -- Jellyfin bundles its frontend with content-hashed filenames; use
    -- extension-based patterns rather than enumerating individual files.
    -------------------------------------------------------------------------
    {
      name    = "web root",
      method  = "GET",
      paths   = { [[^/web$]], [[^/web/$]], [[^/web/index\.html$]] },
      no_body = true,
    },
    {
      name    = "web config",
      method  = "GET",
      paths   = { [[^/web/config\.json$]], [[^/web/serviceworker\.js$]] },
      no_body = true,
    },
    {
      name    = "web static",
      method  = "GET",
      -- hashed JS/CSS/font/image bundles, e.g.
      -- /web/14245.f517756c675c2040ffba.css
      -- /web/node_modules.@jellyfin.sdk.bundle.js
      -- /web/noto-sans-latin-400-normal.f5cd7b617bcb047bfaa4.woff2
      paths   = {
        [[^/web/[^/]+\.(js|css|woff2|woff|ttf|png|svg|ico|json|map)$]],
        -- /web/assets/img/devices/firefox.svg
        [[^/web/assets/img/(?:[^/]+/)?[^/]+\.svg$]],
        [[^/web/themes/[^/]+/[^/]+\.css$]],
        [[^/web/ConfigurationPages$]],
      },
      no_body = true,
    },
    {
      -- Plugin-provided HTML config page, e.g. /web/configurationpage?name=Home%20Screen%20Sections
      name    = "web configurationpage",
      method  = "GET",
      paths   = { [[^/web/(?:C|c)onfigurationpage$]] },
      no_body = true,
      query   = T.object(
        { name = T.string({ max = 128, not_match = "[\\x00-\\x1f]" }) },
        { required = { name = true } }
      ),
    },

    -------------------------------------------------------------------------
    -- Branding
    -------------------------------------------------------------------------
    { name="branding",              method="GET",        path=[[^/Branding$]],               no_body=true },
    { name="branding config",       method="GET",        path=[[^/Branding/Configuration$]], no_body=true },
    { name="branding splashscreen", methods={"GET","POST"}, path=[[^/Branding/Splashscreen$]] },

    -------------------------------------------------------------------------
    -- System
    -------------------------------------------------------------------------
    { name="system config",          methods={"GET","POST"}, path=[[^/System/Configuration$]] },
    { name="system config livetv",   methods={"GET","POST"}, path=[[^/System/Configuration/livetv$]] },
    { name="system config branding", method="POST",          path=[[^/System/Configuration/branding$]] },
    -- apps/dashboard/controllers/networking.js:63 - admin Networking
    -- settings page saves via POST; GET (open the page) was already covered.
    { name="system config network",  methods={"GET","POST"},          path=[[^/System/Configuration/network$]] },
    { name="system config xbmc",     methods={"GET","POST"}, path=[[^/System/Configuration/xbmcmetadata$]] },
    { name="system config encoding", methods={"GET","POST"}, path=[[^/System/Configuration/encoding$]] },
    { name="system config metadata", methods={"GET","POST"}, path=[[^/System/Configuration/metadata$]] },
    { name="system logs",            method="GET",           path=[[^/System/Logs$]],                       no_body=true },
    { name="system endpoint",        method="GET",           path=[[^/System/Endpoint$]],                   no_body=true },
    { name="system info",            method="GET",           path=[[^/System/Info$]],                       no_body=true },
    { name="system info storage",    method="GET",           path=[[^/System/Info/Storage$]],               no_body=true },
    { name="system info public",     method="GET",           path=[[^/System/Info/Public$]],                no_body=true },
    { name="system activitylog",     method="GET",           path=[[^/System/ActivityLog/Entries$]],        no_body=true },

    -------------------------------------------------------------------------
    -- Localization
    -------------------------------------------------------------------------
    { name="locale options",  method="GET", path=[[^/Localization/Options$]],        no_body=true },
    { name="locale ratings",  method="GET", path=[[^/Localization/ParentalRatings$]], no_body=true },
    { name="locale cultures", method="GET", path=[[^/Localization/(?:C|c)ultures$]], no_body=true },
    { name="locale countries",method="GET", path=[[^/Localization/(?:C|c)ountries$]], no_body=true },

    -------------------------------------------------------------------------
    -- Auth
    -------------------------------------------------------------------------
    { name="auth providers",  method="GET", path=[[^/Auth/Providers$]],              no_body=true },
    { name="auth keys",       method="GET", path=[[^/Auth/Keys$]],                   no_body=true },
    -- apps/dashboard/features/keys/api/useCreateKey.ts,useRevokeKey.ts -
    -- generated SDK, camelCase; key is server-issued (Guid.ToString("N") -
    -- hex32), route param.
    {
      name   = "auth keys create",
      method = "POST",
      path   = [[^/Auth/Keys$]],
      query  = T.object({ app = T.string({ max = 128, not_match = "[\\x00-\\x1f]" }) }, { required = { app = true } }),
    },
    { name="auth keys revoke", method="DELETE", path=[[^/Auth/Keys/]] .. HEX32 .. [[$]] },
    { name="auth pwproviders",method="GET", path=[[^/Auth/PasswordResetProviders$]], no_body=true },

    -------------------------------------------------------------------------
    -- Environment (admin: file browser for library setup)
    -------------------------------------------------------------------------
    { name="env dirbrowser",    method="GET",  path=[[^/Environment/DefaultDirectoryBrowser$]], no_body=true },
    { name="env drives",        method="GET",  path=[[^/Environment/Drives$]],                  no_body=true },
    { name="env dircontents",   method="GET",  path=[[^/Environment/DirectoryContents$]],       no_body=true },
    { name="env parentpath",    method="GET",  path=[[^/Environment/ParentPath$]],              no_body=true },
    { name="env validatepath",  method="POST", path=[[^/Environment/ValidatePath$]] },

    -------------------------------------------------------------------------
    -- Libraries
    -------------------------------------------------------------------------
    { name="lib options",  method="GET",        path=[[^/Libraries/AvailableOptions$]], no_body=true },
    { name="lib folders",  method="GET",        path=[[^/Library/MediaFolders$]],       no_body=true },
    { name="lib virtual",  methods={"GET","POST"}, path=[[^/Library/VirtualFolders$]] },

    -------------------------------------------------------------------------
    -- Display Preferences
    -------------------------------------------------------------------------
    -- DisplayPreferencesController: displayPreferencesId is any free-form
    -- string, not a fixed keyword set - the server Guid.TryParse()s it and
    -- falls back to MD5-hashing the raw string if it isn't one. "usersettings"
    -- and "livetv" are just the values the official web client happens to
    -- use; other clients (e.g. Android TV) send a GUID instead. client is a
    -- required query param; userId is optional (implied by auth token).
    {
      name    = "displayprefs",
      methods = { "GET", "POST" },
      path    = [[^/DisplayPreferences/[0-9A-Za-z_.-]+$]],
      query   = T.object(
        {
          client = T.string({ max = 64, not_match = "[\\x00-\\x1f]" }),
          userId = T.nullable(jf_id()),
        },
        { required = { client = true } }
      ),
    },

    -------------------------------------------------------------------------
    -- Repositories / Packages / Plugins / Backup
    -------------------------------------------------------------------------
    { name="repositories",      methods={"GET","POST"}, path=[[^/Repositories$]] },
    { name="packages",          method="GET",           path=[[^/Packages$]],   no_body=true },
    { name="packages named",    method="GET",           path=[[^/Packages/(?:AudioDB|MusicBrainz|OMDb|SSO-Auth|Studio Images|TMDb)$]], no_body=true },
    { name="packages installed",methods={"GET","POST"}, paths={
        [[^/Packages/Installed/Home%20Screen%20Sections$]],
        [[^/Packages/Installed/Home Screen Sections$]],
    }},
    { name="plugins",           method="GET", path=[[^/Plugins$]],                                          no_body=true },
    { name="plugins version",   method="GET", path=[[^/Plugins/]] .. HEX32 .. [[/[0-9.]+$]],               no_body=true },
    { name="plugins image",     method="GET", path=[[^/Plugins/]] .. HEX32 .. [[/[0-9.]+/Image$]],         no_body=true },
    { name="backup",            method="GET", path=[[^/Backup$]],                                           no_body=true },

    -------------------------------------------------------------------------
    -- Users
    -------------------------------------------------------------------------
    { name="users list",        methods={"GET","POST"}, paths={ [[^/Users$]], [[^/users$]] } },
    { name="users public",      method="GET",  paths={ [[^/Users/Public$]], [[^/users/public$]] }, no_body=true },
    { name="users me",          method="GET",  path=[[^/Users/Me$]],             no_body=true },
    { name="users new",         method="POST", path=[[^/Users/New$]] },
    { name="users auth",        method="POST", paths={
        [[^/Users/AuthenticateByName$]],
        [[^/Users/authenticatebyname$]],
    }},
    -- controllers/session/login/index.js reads json.Secret/data.Secret from
    -- this same QuickConnect flow's own request/response traffic (see
    -- "quickconnect connect" below) - PascalCase, not the camelCase the
    -- C# parameter name (secret) would suggest.
    {
      name          = "users auth quickconnect",
      method        = "POST",
      path          = [[^/Users/AuthenticateWithQuickConnect$]],
      content_types = { "application/json" },
      json          = T.object(
        { Secret = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }) },
        { required = { Secret = true } }
      ),
    },
    {
      name    = "users password",
      method  = "POST",
      path    = [[^/Users/Password$]],
      query   = T.object({ userId = T.nullable(jf_id()) }),
    },
    {
      name          = "users forgotpassword",
      method        = "POST",
      path          = [[^/Users/ForgotPassword$]],
      content_types = { "application/json" },
    },
    {
      name          = "users forgotpassword pin",
      method        = "POST",
      path          = [[^/Users/ForgotPassword/Pin$]],
      content_types = { "application/json" },
    },
    {
      name    = "users by id",
      methods = { "GET", "POST", "DELETE" },
      path    = "^/Users/" .. ID .. "$",
    },
    { name="users image primary", method="GET",        path="^/Users/" .. ID .. "/Images/Primary$",  no_body=true },
    { name="users configuration", methods={"GET","POST"}, path="^/Users/" .. ID .. "/Configuration$" },
    { name="users policy",        method="POST",           path="^/Users/" .. ID .. "/Policy$" },
    { name="users grouping",      method="GET",            path="^/Users/" .. ID .. "/GroupingOptions$", no_body=true },
    {
      name    = "userviews grouping",
      method  = "GET",
      path    = [[^/UserViews/GroupingOptions$]],
      no_body = true,
      query   = T.object({ userId = T.nullable(jf_id()) }),
    },
    { name="users items",         method="GET",            path="^/Users/" .. ID .. "/Items$",           no_body=true },
    { name="users items latest",  method="GET",            path="^/Users/" .. ID .. "/Items/Latest$",    no_body=true },
    { name="users items resume",  method="GET",            path="^/Users/" .. ID .. "/Items/Resume$",    no_body=true },
    { name="users items by id",   method="GET",            path="^/Users/" .. ID .. "/Items/" .. ID .. "$", no_body=true },
    { name="users items intros",  method="GET",            path="^/Users/" .. ID .. "/Items/" .. ID .. "/Intros$", no_body=true },
    { name="items intros",        method="GET",            path="^/Items/" .. ID .. "/Intros$", no_body=true },
    { name="users items special", method="GET",            path="^/Users/" .. ID .. "/Items/" .. ID .. "/SpecialFeatures$", no_body=true },
    {
      name    = "items special",
      method  = "GET",
      path    = "^/Items/" .. ID .. "/SpecialFeatures$",
      no_body = true,
      query   = T.object({ userId = T.nullable(jf_id()) }),
    },
    -- Mark / unmark played, legacy user-in-path form. datePlayed is
    -- [FromQuery] DateTime? in PlaystateController.MarkPlayedItem - optional,
    -- not required.
    {
      name   = "played items mark",
      method = "POST",
      path   = "^/Users/" .. ID .. "/PlayedItems/[0-9A-Za-z_.-]+$",
      query  = T.object({ DatePlayed = T.nullable(T.iso8601()) }),
    },
    {
      name   = "played items unmark",
      method = "DELETE",
      path   = "^/Users/" .. ID .. "/PlayedItems/[0-9A-Za-z_.-]+$",
    },
    -- Mark / unmark played, current form (userId implied by auth token, or
    -- passed as an optional query param instead of a path segment).
    {
      name   = "userplayeditems mark",
      method = "POST",
      path   = "^/UserPlayedItems/[0-9A-Za-z_.-]+$",
      query  = T.object({
        userId     = T.nullable(jf_id()),
        datePlayed = T.nullable(T.iso8601()),
      }),
    },
    {
      name   = "userplayeditems unmark",
      method = "DELETE",
      path   = "^/UserPlayedItems/[0-9A-Za-z_.-]+$",
      query  = T.object({ userId = T.nullable(jf_id()) }),
    },
    { name="favorite items", methods={"POST","DELETE"}, path="^/Users/" .. ID .. "/FavoriteItems/[0-9A-Za-z_.-]+$" },
    -- Current form of favorite items (userId implied by auth token, or
    -- passed as an optional query param instead of a path segment) -
    -- same legacy/current split as userplayeditems above.
    {
      name    = "userfavoriteitems",
      methods = { "POST", "DELETE" },
      path    = "^/UserFavoriteItems/[0-9A-Za-z_.-]+$",
      query   = T.object({ userId = T.nullable(jf_id()) }),
    },

    -------------------------------------------------------------------------
    -- User-level convenience endpoints
    -------------------------------------------------------------------------
    { name="userimage",    method="GET", path=[[^/UserImage$]],          no_body=true },
    { name="useritems resume", method="GET", path=[[^/UserItems/Resume$]], no_body=true },
    { name="userviews",    method="GET", path=[[^/UserViews$]],          no_body=true },

    -------------------------------------------------------------------------
    -- Items
    -------------------------------------------------------------------------
    { name="items",              methods={"GET","POST"}, path=[[^/Items$]] },
    -- GET: fetch. POST: ItemUpdateController.UpdateItem, save from the
    -- metadata editor (scripts/metadataEditor.js) - body is the full
    -- BaseItemDto (100+ fields), left unvalidated beyond content-type, same
    -- as this file's convention for other large nested-object bodies.
    -- DELETE: scripts/deleteHelper.js's item-delete flow.
    { name="items by id",        methods={"GET","POST","DELETE"}, path="^/Items/" .. ID .. "$", content_types={"application/json"} },
    { name="items counts",       method="GET",           path=[[^/Items/Counts$]],         no_body=true },
    { name="items latest",       method="GET",           path=[[^/Items/Latest$]],         no_body=true },
    { name="items similar",      method="GET",           path="^/Items/" .. ID .. "/Similar$",             no_body=true },
    { name="items refresh",      method="POST",          path="^/Items/" .. ID .. "/Refresh$" },
    { name="items metadata editor", method="GET",        path="^/Items/" .. ID .. "/MetadataEditor$",      no_body=true },
    { name="items download",     method="GET",           path="^/Items/" .. ID .. "/Download$",            no_body=true },
    { name="items externalids",  method="GET",           path="^/Items/" .. ID .. "/ExternalIdInfos$",     no_body=true },
    -- itemidentifier.js:94 builds this URL dynamically per item type -
    -- `Items/RemoteSearch/${currentItemType}` - confirming all 9 ItemLookupController
    -- variants are real traffic, not just the one ("Book") previously
    -- whitelisted. Body is RemoteSearchQuery<T> (generic, type-varying
    -- nested SearchInfo), left unvalidated beyond content-type, same
    -- convention as "items by id"'s POST above.
    {
      name          = "items remotesearch",
      method        = "POST",
      path          = [[^/Items/RemoteSearch/(?:Movie|Trailer|MusicVideo|Series|BoxSet|MusicArtist|MusicAlbum|Person|Book)$]],
      content_types = { "application/json" },
    },
    -- itemidentifier.js:269 - applies a chosen search result to the item.
    {
      name          = "items remotesearch apply",
      method        = "POST",
      path          = "^/Items/RemoteSearch/Apply/" .. ID .. "$",
      content_types = { "application/json" },
    },
    {
      name    = "items instantmix",
      method  = "GET",
      path    = "^/Items/" .. ID .. "/InstantMix$",
      no_body = true,
      -- apiClient.getInstantMixFromItem(item.Id, options) - userId/limit are
      -- the only scalar params confirmed as real (playbackmanager.js:4018);
      -- fields/enableImageTypes are CSV enum lists, bounded but not
      -- enumerated (same tradeoff as elsewhere for those two fields).
      query   = T.object({
        userId           = T.nullable(jf_id()),
        limit            = T.nullable(T.number_query({ integer = true, min = 1 })),
        enableImages     = T.bool_query(),
        enableUserData   = T.bool_query(),
        imageTypeLimit   = T.nullable(T.number_query({ integer = true, min = 0 })),
        fields           = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
        enableImageTypes = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
      }),
    },
    -- filterdialog.js / useFetchItems.ts's getQueryFiltersLegacy call -
    -- powers the library filter dropdown.
    {
      name    = "items filters",
      method  = "GET",
      path    = [[^/Items/Filters$]],
      no_body = true,
      query   = T.object({
        userId           = T.nullable(jf_id()),
        parentId         = T.nullable(jf_id()),
        includeItemTypes = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
        mediaTypes       = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
      }),
    },
    { name="items thememedia",   method="GET",           path="^/Items/" .. ID .. "/ThemeMedia$",          no_body=true },
    { name="items remoteimages", method="GET",           path="^/Items/" .. ID .. "/RemoteImages/Providers$", no_body=true },
    { name="items playbackinfo", methods={"GET","POST"}, path="^/Items/" .. ID .. "/PlaybackInfo$" },
    -- Images
    { name="items images",          method="GET", path="^/Items/" .. ID .. "/Images$",           no_body=true },
    { name="items images thumb",    method="GET", path="^/Items/" .. ID .. "/Images/Thumb$",     no_body=true },
    { name="items images logo",     method="GET", path="^/Items/" .. ID .. "/Images/Logo$",      no_body=true },
    { name="items images primary",  methods={"GET","POST"}, path="^/Items/" .. ID .. "/Images/Primary$" },
    { name="items images backdrop", method="GET", path="^/Items/" .. ID .. "/Images/Backdrop$",  no_body=true },
    { name="items images backdrop0",method="GET", path="^/Items/" .. ID .. "/Images/Backdrop/0$", no_body=true },

    -------------------------------------------------------------------------
    -- Shows
    -------------------------------------------------------------------------
    { name="shows seasons",  method="GET", path="^/Shows/" .. ID .. "/Seasons/?$",  no_body=true },
    { name="shows episodes", method="GET", path="^/Shows/" .. ID .. "/Episodes$",   no_body=true },
    { name="shows upcoming", method="GET", path=[[^/Shows/Upcoming$]],              no_body=true },
    { name="shows nextup",   method="GET", path=[[^/Shows/NextUp$]],                no_body=true },

    -------------------------------------------------------------------------
    -- Audio
    -------------------------------------------------------------------------
    { name="audio lyrics",        methods={"GET","POST","DELETE"}, path="^/Audio/" .. ID .. "/Lyrics$" },
    { name="audio lyrics remote", method="GET",                    path="^/Audio/" .. ID .. "/RemoteSearch/Lyrics$", no_body=true },
    -- AudioController: direct-play/transcode streaming, mirrors the "videos
    -- stream"/"videos stream <ext>" routes below. Query params (container,
    -- audioCodec, bitrate, etc.) are numerous, transcoding-engine-specific,
    -- and already unvalidated for video's equivalent routes - same here.
    { name="audio stream",     method="GET", path="^/Audio/" .. ID .. "/stream$" },
    { name="audio stream ext", method="GET", path="^/Audio/" .. ID .. "/stream\\.[A-Za-z0-9]{1,10}$", no_body=true },
    -- UniversalAudioController: adaptive-streaming endpoint most mobile/TV
    -- clients use for audio playback in preference to plain /stream.
    { name="audio universal",  method="GET", path="^/Audio/" .. ID .. "/universal$" },

    -------------------------------------------------------------------------
    -- Videos / videos (lowercase used for HLS streaming segments)
    -------------------------------------------------------------------------
    { name="videos",               methods={"GET","POST"}, path=[[^/Videos$]] },
    { name="videos active enc",    methods={"GET","POST","DELETE"}, path=[[^/Videos/ActiveEncodings$]] },
    { name="videos subtitles",     method="POST",          path="^/Videos/" .. ID .. "/Subtitles$" },
    { name="videos stream post",   method="POST",          path="^/Videos/" .. ID .. "/stream$" },
    { name="videos stream get",    method="GET",           path="^/Videos/" .. ID .. "/stream$" },
    { name="videos stream mp4",    method="GET",           path="^/Videos/" .. HEX32 .. "/stream\\.mp4$",   no_body=true },
    { name="videos stream mkv",    method="GET",           path="^/Videos/" .. HEX32 .. "/stream\\.mkv$",   no_body=true },
    { name="videos stream webm",   method="GET",           path="^/Videos/" .. HEX32 .. "/stream\\.webm$",  no_body=true },
    -- subtitle streams. SubtitleController's real route param is {routeFormat}
    -- (free-form in the C# signature), but the web client's SubtitleProfiles
    -- (browserDeviceProfile.js) only ever request vtt/ass/ssa/pgssub - never
    -- js/subrip.js, which this route previously (incorrectly) hardcoded.
    -- StreamInfo.cs always builds the URL with the startPositionTicks segment
    -- present (even when 0), so the 5-segment "no ticks" form is legacy/dead
    -- but kept for safety since SubtitleController still defines it.
    -- Server's default DeliveryUrl extension is .vtt; the web client
    -- string-replaces it for two other real cases: 'ass'/'ssa'/'pgssub'
    -- (browserDeviceProfile.js's SubtitleProfiles, tells the server which
    -- pass-through formats it accepts) and '.js' (getTextTrackUrl() in
    -- htmlVideoPlayer/plugin.js, still actively used by
    -- renderSubtitlesWithCustomElement's fetchSubtitles() for the custom
    -- text-overlay renderer). 'subrip.js' has zero references anywhere in
    -- this client version - dropped, unlike plain '.js'.
    {
      name    = "videos subtitle stream",
      method  = "GET",
      paths   = {
        "^/Videos/" .. ID .. "/" .. OPAQUE_ID .. "/Subtitles/[0-9]+/Stream\\.(?:vtt|ass|ssa|pgssub|js)$",
        "^/Videos/" .. ID .. "/" .. OPAQUE_ID .. "/Subtitles/[0-9]+/[0-9]+/Stream\\.(?:vtt|ass|ssa|pgssub|js)$",
      },
      no_body = true,
    },
    { name="videos subtitle delete", method="DELETE", path="^/Videos/" .. ID .. "/Subtitles/[0-9]+$" },
    -- No web-client caller found for isPerfectMatch on the search route
    -- (subtitleeditor.js's actual call omits it); left unvalidated.
    { name="items subtitle search",   method="GET",  path="^/Items/" .. ID .. "/RemoteSearch/Subtitles/[A-Za-z-]{2,35}$", no_body=true },
    { name="items subtitle download", method="POST", path="^/Items/" .. ID .. "/RemoteSearch/Subtitles/" .. OPAQUE_ID .. "$" },
    -- HLS streaming (lowercase /videos/)
    {
      name    = "hls playlist",
      method  = "GET",
      paths   = {
        "^/videos/" .. ID .. "/(?:master|main)\\.m3u8$",
        "^/videos/" .. UUID .. "/(?:master|live)\\.m3u8$",
      },
      no_body = true,
    },
    {
      name    = "hls segments",
      method  = "GET",
      paths   = {
        -- /videos/c1909159-c1fa-11af-3447-9e34339ceacf/hls1/main/-1.mp4
        "^/videos/" .. ID .. "/hls1/main/[0-9-]+\\.(?:ts|mp4)$",
        "^/videos/" .. ID .. "/hls/[0-9a-fA-F_-]+\\.ts$",
      },
      no_body = true,
    },

    -------------------------------------------------------------------------
    -- Trickplay (seek-bar hover thumbnails)
    -------------------------------------------------------------------------
    -- No web-client caller found for the HLS-tiles-playlist variant (only
    -- the per-tile .jpg form, for the seek-bar hover preview) - left
    -- unvalidated beyond path/method rather than guess at query shape.
    {
      name    = "trickplay tiles",
      method  = "GET",
      path    = "^/Videos/" .. ID .. "/Trickplay/[0-9]+/tiles\\.m3u8$",
      no_body = true,
    },
    -- controllers/playback/video/index.js builds this URL with
    -- { ApiKey: apiClient.accessToken(), MediaSourceId: mediaSourceId } -
    -- PascalCase, since <img>-style URLs can't carry an Authorization header
    -- and go through apiClient.getUrl()'s raw query-building path rather
    -- than the generated SDK (which would camelCase these).
    {
      name    = "trickplay tile",
      method  = "GET",
      path    = "^/Videos/" .. ID .. "/Trickplay/[0-9]+/[0-9]+\\.jpg$",
      no_body = true,
      query   = T.object({
        ApiKey        = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
        MediaSourceId = T.nullable(jf_id()),
      }),
    },

    -------------------------------------------------------------------------
    -- FallbackFont (ASS/SSA subtitle rendering)
    -------------------------------------------------------------------------
    { name="fallbackfont list", method="GET", path=[[^/FallbackFont/Fonts$]],             no_body=true },
    { name="fallbackfont file", method="GET", path=[[^/FallbackFont/Fonts/]] .. OPAQUE_ID .. [[$]], no_body=true },

    -------------------------------------------------------------------------
    -- Media Segments
    -------------------------------------------------------------------------
    { name="mediasegments", method="GET", path="^/MediaSegments/" .. ID .. "$", no_body=true },

    -------------------------------------------------------------------------
    -- Playback
    -------------------------------------------------------------------------
    { name="playback bitratetest", method="GET", path=[[^/Playback/BitrateTest$]], no_body=true },

    -------------------------------------------------------------------------
    -- Sessions
    -------------------------------------------------------------------------
    { name="sessions",                 methods={"GET","POST"}, path=[[^/Sessions$]] },
    { name="sessions capabilities",    method="POST",          path=[[^/Sessions/Capabilities$]] },
    { name="sessions capabilities full",method="POST",         path=[[^/Sessions/Capabilities/Full$]] },
    { name="sessions message",         method="POST",          path="^/Sessions/" .. ID .. "/Message$" },
    -- Remote-control commands (SessionController). These go through
    -- apiClient.sendPlayCommand/sendCommand/sendPlayStateCommand - methods
    -- of the "jellyfin-apiclient" npm package (external dependency, not
    -- vendored in app-sources/ - only its own connection-management subset
    -- is vendored), so the exact wire-format query/body key casing can't be
    -- confirmed against source. Left unvalidated beyond path/method, same as
    -- the already-established "sessions playing"/"sessions playing progress"
    -- routes above, rather than risk blocking real traffic on a guessed casing.
    {
      name   = "sessions playing (session)",
      method = "POST",
      path   = "^/Sessions/" .. OPAQUE_ID .. "/Playing$",
    },
    {
      name   = "sessions playing command",
      method = "POST",
      path   = "^/Sessions/" .. OPAQUE_ID .. "/Playing/" .. PLAYSTATE_COMMAND .. "$",
    },
    {
      name   = "sessions command",
      method = "POST",
      path   = "^/Sessions/" .. OPAQUE_ID .. "/Command$",
    },
    { name="sessions playing",         method="POST",          path=[[^/Sessions/Playing$]] },
    { name="sessions playing progress",method="POST",          path=[[^/Sessions/Playing/Progress$]] },
    { name="sessions playing stop",    method="POST",          path=[[^/Sessions/Playing/Stop$]] },
    { name="sessions playing stopped", method="POST",          path=[[^/Sessions/Playing/Stopped$]] },

    -------------------------------------------------------------------------
    -- SyncPlay
    -------------------------------------------------------------------------
    { name="syncplay list",       method="GET",  path=[[^/SyncPlay/List$]],       no_body=true },
    { name="syncplay pause",      method="GET",  path=[[^/SyncPlay/Pause$]],      no_body=true },
    { name="syncplay buffering",  method="GET",  path=[[^/SyncPlay/Buffering$]],  no_body=true },
    { name="syncplay new",        method="POST", path=[[^/SyncPlay/New$]] },
    { name="syncplay ready",      method="POST", path=[[^/SyncPlay/Ready$]] },
    { name="syncplay newqueue",   method="POST", path=[[^/SyncPlay/SetNewQueue$]] },

    -------------------------------------------------------------------------
    -- Live TV
    -------------------------------------------------------------------------
    { name="livetv guideinfo",    method="GET",          path=[[^/LiveTv/GuideInfo$]],                              no_body=true },
    { name="livetv tunerhosts",   methods={"POST","DELETE"}, path=[[^/LiveTv/TunerHosts$]] },
    { name="livetv listprov sd",  method="GET",          path=[[^/LiveTv/ListingProviders/SchedulesDirect/Countries$]], no_body=true },
    { name="livetv listprov def", method="GET",          path=[[^/LiveTv/ListingProviders/Default$]],              no_body=true },
    { name="livetv listprov",     method="POST",         path=[[^/LiveTv/ListingProviders$]] },
    { name="livetv tuner types",  method="GET",          path=[[^/LiveTv/TunerHosts/Types$]],                      no_body=true },
    { name="livetv discover",     method="GET",          path=[[^/LiveTv/Tuners/Discover$]],                       no_body=true },
    { name="livetv channels",     method="GET",          path=[[^/LiveTv/Channels$]],                              no_body=true },
    { name="livetv channel by id",method="GET",          path="^/LiveTv/Channels/" .. ID .. "$",                   no_body=true },
    { name="livetv timers",       method="GET",          path=[[^/LiveTv/Timers$]],                                no_body=true },
    -- DVR timer CRUD (recordingeditor.js, recordinghelper.js). timerId is a
    -- `string` route param server-side (opaque, not GUID). TimerInfoDto is
    -- a large nested object - unvalidated beyond content-type, same
    -- convention as other big DTOs above.
    {
      name          = "livetv timer by id",
      methods       = { "GET", "POST", "DELETE" },
      path          = "^/LiveTv/Timers/" .. OPAQUE_ID .. "$",
      content_types = { "application/json" },
    },
    {
      name          = "livetv timers create",
      method        = "POST",
      path          = [[^/LiveTv/Timers$]],
      content_types = { "application/json" },
    },
    { name="livetv recordings",   method="GET",          path=[[^/LiveTv/Recordings$]],                            no_body=true },
    { name="livetv rec folders",  method="GET",          path=[[^/LiveTv/Recordings/Folders$]],                    no_body=true },
    { name="livetv series timers",method="GET",          path=[[^/LiveTv/SeriesTimers$]],                          no_body=true },
    -- Series-recording CRUD (seriesrecordingeditor.js, guide.js). Same
    -- SeriesTimerInfoDto/opaque-timerId reasoning as above.
    {
      name          = "livetv seriestimer by id",
      methods       = { "GET", "POST", "DELETE" },
      path          = "^/LiveTv/SeriesTimers/" .. OPAQUE_ID .. "$",
      content_types = { "application/json" },
    },
    {
      name          = "livetv seriestimers create",
      method        = "POST",
      path          = [[^/LiveTv/SeriesTimers$]],
      content_types = { "application/json" },
    },
    { name="livetv prog rec",     method="GET",          path=[[^/LiveTv/Programs/Recommended$]],                  no_body=true },
    { name="livetv programs",     method="GET",          path=[[^/LiveTv/Programs$]],                              no_body=true },

    -------------------------------------------------------------------------
    -- Live Streams
    -------------------------------------------------------------------------
    { name="livestreams mediainfo", method="POST", path=[[^/LiveStreams/MediaInfo$]] },
    -- Required to start playback of any tuner-based live channel
    -- (playbackmanager.js:567). Confirmed real query keys are PascalCase
    -- (ItemId, PlaySessionId, MaxStreamingBitrate, ...) plus a JSON body -
    -- same large-transcoding-surface treatment as video/audio stream routes.
    { name="livestreams open",  method="POST", path=[[^/LiveStreams/Open$]] },
    { name="livestreams close", method="POST", path=[[^/LiveStreams/Close$]] },

    -------------------------------------------------------------------------
    -- Collections, Movies, Playlists
    -------------------------------------------------------------------------
    { name="collections",         method="POST",         path=[[^/Collections$]] },
    -- collectionEditor.js / itemContextMenu.js build these with
    -- { Ids: [...].join(',') } - PascalCase, confirmed via apiClient.getUrl().
    {
      name    = "collections items add",
      method  = "POST",
      path    = "^/Collections/" .. ID .. "/Items$",
      query   = T.object({ Ids = T.string({ max = 8192, not_match = "[\\x00-\\x1f]" }) }, { required = { Ids = true } }),
    },
    {
      name    = "collections items remove",
      method  = "DELETE",
      path    = "^/Collections/" .. ID .. "/Items$",
      query   = T.object({ Ids = T.string({ max = 8192, not_match = "[\\x00-\\x1f]" }) }, { required = { Ids = true } }),
    },
    { name="movies rec",          method="GET",          path=[[^/Movies/Recommendations$]], no_body=true },
    { name="playlists",           methods={"GET","POST"}, path=[[^/Playlists$]] },
    { name="playlists by id",     methods={"GET","POST"}, path="^/Playlists/" .. ID .. "$" },
    { name="playlists items",     method="GET",           path="^/Playlists/" .. ID .. "/Items$",           no_body=true },
    -- playlisteditor.ts:139 calls the generated SDK with { playlistId, ids,
    -- userId } literally - camelCase, SDK-confirmed.
    {
      name   = "playlists items add",
      method = "POST",
      path   = "^/Playlists/" .. ID .. "/Items$",
      query  = T.object(
        {
          ids    = T.string({ max = 8192, not_match = "[\\x00-\\x1f]" }),
          userId = T.nullable(jf_id()),
        },
        { required = { ids = true } }
      ),
    },
    -- itemContextMenu.js builds this with { EntryIds: [...].join(',') } -
    -- PascalCase, confirmed via apiClient.getUrl(). Bounded charset only
    -- (not an ID-shaped pattern): PlaylistItemId isn't necessarily
    -- GUID-shaped, and a strict comma-list regex isn't reversable by the
    -- test generator's auto "valid" synthesis (see gen.lua's raw_valid).
    {
      name   = "playlists items remove",
      method = "DELETE",
      path   = "^/Playlists/" .. ID .. "/Items$",
      query  = T.object(
        { EntryIds = T.string({ max = 8192, not_match = "[\\x00-\\x1f]" }) },
        { required = { EntryIds = true } }
      ),
    },
    -- itemContextMenu.js:624,632 - playlistId/itemId route params, both
    -- opaque strings server-side (MoveItem's C# signature types them
    -- `string`, not `Guid`); newIndex is path-constrained to digits already.
    {
      name   = "playlists items move",
      method = "POST",
      path   = "^/Playlists/" .. OPAQUE_ID .. "/Items/" .. OPAQUE_ID .. "/Move/[0-9]+$",
    },
    { name="playlists users",     method="GET",           path="^/Playlists/" .. ID .. "/Users$",           no_body=true },
    { name="playlists users byid",method="GET",           path="^/Playlists/" .. ID .. "/Users/" .. ID .. "$", no_body=true },

    -------------------------------------------------------------------------
    -- Browse collections: Artists, Persons, Genres, Studios, Channels, Devices
    -------------------------------------------------------------------------
    { name="artists",   method="GET", path=[[^/Artists$]],   no_body=true },
    -- Same huge optional-filter query surface as "artists" above (already
    -- unvalidated there); must come before "artists by name" below, since
    -- that catch-all would otherwise match "AlbumArtists" as a literal name.
    { name="artists albumartists", method="GET", path=[[^/Artists/AlbumArtists$]], no_body=true },
    -- apiClient.getArtist(name, userId) / itemDetails/index.js:82,74,78 -
    -- userId is the only param these callers pass; names are free-form
    -- display strings (spaces, unicode, punctuation), so a bounded
    -- not-slash charset rather than an ID pattern.
    {
      name    = "artists by name",
      method  = "GET",
      path    = [[^/Artists/[^/\x00-\x1f]{1,200}$]],
      no_body = true,
      query   = T.object({ userId = T.nullable(jf_id()) }),
    },
    { name="persons",   method="GET", path=[[^/Persons$]],   no_body=true },
    { name="genres",    method="GET", path=[[^/Genres$]],    no_body=true },
    {
      name    = "genres by name",
      method  = "GET",
      path    = [[^/Genres/[^/\x00-\x1f]{1,200}$]],
      no_body = true,
      query   = T.object({ userId = T.nullable(jf_id()) }),
    },
    -- No base "GET /MusicGenres" list route exists in this policy or is
    -- called by this web client (only apiclient.d.ts's type declaration,
    -- no real call site) - itemDetails/index.js:78 only calls the by-name form.
    {
      name    = "musicgenres by name",
      method  = "GET",
      path    = [[^/MusicGenres/[^/\x00-\x1f]{1,200}$]],
      no_body = true,
      query   = T.object({ userId = T.nullable(jf_id()) }),
    },
    { name="studios",   method="GET", path=[[^/Studios$]],   no_body=true },
    { name="channels",  method="GET", path=[[^/Channels$]],  no_body=true },
    { name="devices",   method="GET", path=[[^/Devices$]],   no_body=true },
    -- apps/dashboard/features/devices/api/useDeleteDevice.ts,
    -- useUpdateDevice.ts - generated SDK, camelCase.
    {
      name   = "devices delete",
      method = "DELETE",
      path   = [[^/Devices$]],
      query  = T.object({ id = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }) }, { required = { id = true } }),
    },
    {
      name          = "devices options",
      method        = "POST",
      path          = [[^/Devices/Options$]],
      query         = T.object({ id = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }) }, { required = { id = true } }),
      content_types = { "application/json" },
    },

    -------------------------------------------------------------------------
    -- Scheduled Tasks
    -------------------------------------------------------------------------
    { name="tasks",        method="GET",  path=[[^/ScheduledTasks$]],                                 no_body=true },
    { name="tasks by id",  method="GET",  path="^/ScheduledTasks/" .. HEX32 .. "$",                   no_body=true },
    { name="tasks run",    method="POST", path="^/ScheduledTasks/Running/" .. HEX32 .. "$" },

    -------------------------------------------------------------------------
    -- Quick Connect
    -------------------------------------------------------------------------
    { name="quickconnect initiate", method="POST", path=[[^/QuickConnect/Initiate$]] },
    { name="quickconnect enabled",  method="GET",  path=[[^/QuickConnect/Enabled$]], no_body=true },
    -- controllers/session/login/index.js:67 builds this URL literally as
    -- '/QuickConnect/Connect?Secret=' + json.Secret - confirmed PascalCase.
    {
      name    = "quickconnect connect",
      method  = "GET",
      path    = [[^/QuickConnect/Connect$]],
      no_body = true,
      query   = T.object(
        { Secret = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }) },
        { required = { Secret = true } }
      ),
    },
    -- apps/stable/routes/quickConnect/index.tsx calls the generated SDK
    -- with { code, userId } literally - camelCase, SDK-confirmed.
    {
      name   = "quickconnect authorize",
      method = "POST",
      path   = [[^/QuickConnect/Authorize$]],
      query  = T.object(
        {
          code   = T.string({ max = 32, not_match = "[\\x00-\\x1f]" }),
          userId = T.nullable(jf_id()),
        },
        { required = { code = true } }
      ),
    },

    -------------------------------------------------------------------------
    -- Client log
    -------------------------------------------------------------------------
    { name="clientlog", method="POST", path=[[^/ClientLog/Document$]] },

  },
}
