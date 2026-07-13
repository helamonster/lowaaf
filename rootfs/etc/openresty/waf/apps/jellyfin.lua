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
      -- Per spec this is always exactly "script" - browsers never send any
      -- other value on a service-worker-script fetch.
      ["service-worker"] = T.string({ max = 8, enum = { script = true } }),
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
        [[^/web/assets/img/[^/]+\.svg$]],
        [[^/web/themes/[^/]+/[^/]+\.css$]],
        [[^/web/ConfigurationPages$]],
      },
      no_body = true,
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
    { name="system config network",  method="GET",           path=[[^/System/Configuration/network$]],      no_body=true },
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
    { name="displayprefs settings", methods={"GET","POST"}, path=[[^/DisplayPreferences/usersettings$]] },
    { name="displayprefs livetv",   methods={"GET","POST"}, path=[[^/DisplayPreferences/livetv$]] },

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
    {
      name    = "users by id",
      methods = { "GET", "POST", "DELETE" },
      path    = "^/Users/" .. ID .. "$",
    },
    { name="users image primary", method="GET",        path="^/Users/" .. ID .. "/Images/Primary$",  no_body=true },
    { name="users configuration", methods={"GET","POST"}, path="^/Users/" .. ID .. "/Configuration$" },
    { name="users policy",        method="POST",           path="^/Users/" .. ID .. "/Policy$" },
    { name="users grouping",      method="GET",            path="^/Users/" .. ID .. "/GroupingOptions$", no_body=true },
    { name="users items",         method="GET",            path="^/Users/" .. ID .. "/Items$",           no_body=true },
    { name="users items latest",  method="GET",            path="^/Users/" .. ID .. "/Items/Latest$",    no_body=true },
    { name="users items resume",  method="GET",            path="^/Users/" .. ID .. "/Items/Resume$",    no_body=true },
    { name="users items by id",   method="GET",            path="^/Users/" .. ID .. "/Items/" .. ID .. "$", no_body=true },
    { name="users items intros",  method="GET",            path="^/Users/" .. ID .. "/Items/" .. ID .. "/Intros$", no_body=true },
    { name="users items special", method="GET",            path="^/Users/" .. ID .. "/Items/" .. ID .. "/SpecialFeatures$", no_body=true },
    -- Mark / unmark played: POST requires DatePlayed ISO-8601 query param
    {
      name   = "played items mark",
      method = "POST",
      path   = "^/Users/" .. ID .. "/PlayedItems/[0-9A-Za-z_.-]+$",
      query  = T.object(
        { DatePlayed = T.iso8601() },
        { required = { DatePlayed = true } }
      ),
    },
    {
      name   = "played items unmark",
      method = "DELETE",
      path   = "^/Users/" .. ID .. "/PlayedItems/[0-9A-Za-z_.-]+$",
    },
    { name="favorite items", methods={"POST","DELETE"}, path="^/Users/" .. ID .. "/FavoriteItems/[0-9A-Za-z_.-]+$" },

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
    { name="items by id",        methods={"GET","POST"}, path="^/Items/" .. ID .. "$" },
    { name="items counts",       method="GET",           path=[[^/Items/Counts$]],         no_body=true },
    { name="items latest",       method="GET",           path=[[^/Items/Latest$]],         no_body=true },
    { name="items similar",      method="GET",           path="^/Items/" .. ID .. "/Similar$",             no_body=true },
    { name="items refresh",      method="POST",          path="^/Items/" .. ID .. "/Refresh$" },
    { name="items metadata editor", method="GET",        path="^/Items/" .. ID .. "/MetadataEditor$",      no_body=true },
    { name="items download",     method="GET",           path="^/Items/" .. ID .. "/Download$",            no_body=true },
    { name="items externalids",  method="GET",           path="^/Items/" .. ID .. "/ExternalIdInfos$",     no_body=true },
    { name="items remotesearch book", method="POST",     path=[[^/Items/RemoteSearch/Book$]] },
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

    -------------------------------------------------------------------------
    -- Videos / videos (lowercase used for HLS streaming segments)
    -------------------------------------------------------------------------
    { name="videos",               methods={"GET","POST"}, path=[[^/Videos$]] },
    { name="videos active enc",    methods={"GET","POST","DELETE"}, path=[[^/Videos/ActiveEncodings$]] },
    { name="videos subtitles",     method="POST",          path="^/Videos/" .. ID .. "/Subtitles$" },
    { name="videos stream",        method="POST",          path="^/Videos/" .. ID .. "/stream$" },
    { name="videos stream mp4",    method="GET",           path="^/Videos/" .. HEX32 .. "/stream\\.mp4$",   no_body=true },
    { name="videos stream mkv",    method="GET",           path="^/Videos/" .. HEX32 .. "/stream\\.mkv$",   no_body=true },
    { name="videos stream webm",   method="GET",           path="^/Videos/" .. HEX32 .. "/stream\\.webm$",  no_body=true },
    -- subtitle streams
    {
      name    = "videos subtitle stream",
      method  = "GET",
      paths   = {
        "^/Videos/" .. ID .. "/" .. ID .. "/Subtitles/[0-9]+/[0-9]+/Stream\\.js$",
        "^/Videos/" .. ID .. "/" .. ID .. "/Subtitles/[0-9]+/[0-9]+/Stream\\.subrip\\.js$",
      },
      no_body = true,
    },
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

			--  /videos/c1909159-c1fa-11af-3447-9e34339ceacf/hls1/main/-1.mp4, 
        "^/videos/" .. ID .. "/hls1/main/[0-9-]+\\.(?:ts|mp4)$",
        "^/videos/" .. ID .. "/hls/[0-9a-fA-F_-]+\\.ts$",


      },
      no_body = true,
    },

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
    { name="livetv recordings",   method="GET",          path=[[^/LiveTv/Recordings$]],                            no_body=true },
    { name="livetv rec folders",  method="GET",          path=[[^/LiveTv/Recordings/Folders$]],                    no_body=true },
    { name="livetv series timers",method="GET",          path=[[^/LiveTv/SeriesTimers$]],                          no_body=true },
    { name="livetv prog rec",     method="GET",          path=[[^/LiveTv/Programs/Recommended$]],                  no_body=true },
    { name="livetv programs",     method="GET",          path=[[^/LiveTv/Programs$]],                              no_body=true },

    -------------------------------------------------------------------------
    -- Live Streams
    -------------------------------------------------------------------------
    { name="livestreams mediainfo", method="POST", path=[[^/LiveStreams/MediaInfo$]] },

    -------------------------------------------------------------------------
    -- Collections, Movies, Playlists
    -------------------------------------------------------------------------
    { name="collections",         method="POST",         path=[[^/Collections$]] },
    { name="movies rec",          method="GET",          path=[[^/Movies/Recommendations$]], no_body=true },
    { name="playlists",           methods={"GET","POST"}, path=[[^/Playlists$]] },
    { name="playlists by id",     methods={"GET","POST"}, path="^/Playlists/" .. ID .. "$" },
    { name="playlists items",     method="GET",           path="^/Playlists/" .. ID .. "/Items$",           no_body=true },
    { name="playlists users",     method="GET",           path="^/Playlists/" .. ID .. "/Users$",           no_body=true },
    { name="playlists users byid",method="GET",           path="^/Playlists/" .. ID .. "/Users/" .. ID .. "$", no_body=true },

    -------------------------------------------------------------------------
    -- Browse collections: Artists, Persons, Genres, Studios, Channels, Devices
    -------------------------------------------------------------------------
    { name="artists",   method="GET", path=[[^/Artists$]],   no_body=true },
    { name="persons",   method="GET", path=[[^/Persons$]],   no_body=true },
    { name="genres",    method="GET", path=[[^/Genres$]],    no_body=true },
    { name="studios",   method="GET", path=[[^/Studios$]],   no_body=true },
    { name="channels",  method="GET", path=[[^/Channels$]],  no_body=true },
    { name="devices",   method="GET", path=[[^/Devices$]],   no_body=true },

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

    -------------------------------------------------------------------------
    -- Client log
    -------------------------------------------------------------------------
    { name="clientlog", method="POST", path=[[^/ClientLog/Document$]] },

  },
}
