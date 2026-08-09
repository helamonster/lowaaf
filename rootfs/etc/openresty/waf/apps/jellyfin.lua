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

-- Shared InstantMixController query shape - all 8 GetInstantMixFrom* action
-- methods (Item/Song/Album/Playlist/Artist/MusicGenre, by path segment or
-- by ?id=) bind the identical parameter set. Matches "items instantmix"
-- below exactly (kept separate there since it predates this helper).
local function jf_instantmix_query()
  return {
    userId           = T.nullable(jf_id()),
    limit            = T.nullable(T.number_query({ integer = true, min = 1 })),
    enableImages     = T.bool_query(),
    enableUserData   = T.bool_query(),
    imageTypeLimit   = T.nullable(T.number_query({ integer = true, min = 0 })),
    fields           = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
    enableImageTypes = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
  }
end

-- ItemsController.GetItems query shape (~90 [FromQuery] params) - shared by
-- "items" (GET /Items, ?userId=) and the [Obsolete] "users items" legacy
-- alias (GET /Users/{userId}/Items, userId in path instead). All params are
-- optional; comma/pipe-delimited multi-value fields (locationTypes, fields,
-- includeItemTypes, genres, ids, ...) are kept as bounded plain strings, not
-- per-token-enum-validated, matching this file's existing convention for
-- every other comma/pipe-delimited query field (see jf_instantmix_query,
-- "search hints", "items thememedia", etc.) - ASP.NET's model binders
-- reject unknown tokens server-side; the WAF's job here is bounding length/
-- charset, not re-implementing the enum.
-- include_user_id: false for the path-segment-userId legacy alias, so
-- userId isn't double-accepted as a query key on that route too.
local function jf_get_items_query(include_user_id)
  local q = {
    maxOfficialRating       = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
    hasThemeSong            = T.nullable(T.bool_query()),
    hasThemeVideo           = T.nullable(T.bool_query()),
    hasSubtitles             = T.nullable(T.bool_query()),
    hasSpecialFeature       = T.nullable(T.bool_query()),
    hasTrailer              = T.nullable(T.bool_query()),
    adjacentTo              = T.nullable(jf_id()),
    indexNumber             = T.nullable(T.number_query({ integer = true })),
    parentIndexNumber       = T.nullable(T.number_query({ integer = true })),
    hasParentalRating       = T.nullable(T.bool_query()),
    isHd                    = T.nullable(T.bool_query()),
    is4K                    = T.nullable(T.bool_query()),
    locationTypes           = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    excludeLocationTypes    = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    isMissing               = T.nullable(T.bool_query()),
    isUnaired               = T.nullable(T.bool_query()),
    minCommunityRating      = T.nullable(T.number_query({ min = 0, max = 10 })),
    minCriticRating         = T.nullable(T.number_query({ min = 0, max = 100 })),
    minPremiereDate         = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
    minDateLastSaved        = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
    minDateLastSavedForUser = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
    maxPremiereDate         = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
    hasOverview             = T.nullable(T.bool_query()),
    hasImdbId               = T.nullable(T.bool_query()),
    hasTmdbId               = T.nullable(T.bool_query()),
    hasTvdbId               = T.nullable(T.bool_query()),
    isMovie                 = T.nullable(T.bool_query()),
    isSeries                = T.nullable(T.bool_query()),
    isNews                  = T.nullable(T.bool_query()),
    isKids                  = T.nullable(T.bool_query()),
    isSports                = T.nullable(T.bool_query()),
    excludeItemIds          = T.nullable(T.string({ max = 65536, not_match = "[\\x00-\\x1f]" })),
    startIndex              = T.nullable(T.number_query({ integer = true, min = 0 })),
    limit                   = T.nullable(T.number_query({ integer = true, min = 0 })),
    recursive               = T.nullable(T.bool_query()),
    searchTerm              = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
    sortOrder               = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    parentId                = T.nullable(jf_id()),
    fields                  = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
    excludeItemTypes        = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
    includeItemTypes        = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
    filters                 = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    isFavorite              = T.nullable(T.bool_query()),
    mediaTypes              = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    imageTypes              = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    sortBy                  = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
    isPlayed                = T.nullable(T.bool_query()),
    genres                  = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
    officialRatings         = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
    tags                    = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
    years                   = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
    enableUserData          = T.nullable(T.bool_query()),
    imageTypeLimit          = T.nullable(T.number_query({ integer = true, min = 0 })),
    enableImageTypes        = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    person                  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    personIds               = T.nullable(T.string({ max = 8192, not_match = "[\\x00-\\x1f]" })),
    personTypes             = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
    studios                 = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
    artists                 = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
    excludeArtistIds        = T.nullable(T.string({ max = 8192, not_match = "[\\x00-\\x1f]" })),
    artistIds               = T.nullable(T.string({ max = 8192, not_match = "[\\x00-\\x1f]" })),
    albumArtistIds          = T.nullable(T.string({ max = 8192, not_match = "[\\x00-\\x1f]" })),
    contributingArtistIds   = T.nullable(T.string({ max = 8192, not_match = "[\\x00-\\x1f]" })),
    albums                  = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
    albumIds                = T.nullable(T.string({ max = 8192, not_match = "[\\x00-\\x1f]" })),
    ids                     = T.nullable(T.string({ max = 65536, not_match = "[\\x00-\\x1f]" })),
    videoTypes              = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    minOfficialRating       = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
    isLocked                = T.nullable(T.bool_query()),
    isPlaceHolder           = T.nullable(T.bool_query()),
    hasOfficialRating       = T.nullable(T.bool_query()),
    collapseBoxSetItems     = T.nullable(T.bool_query()),
    minWidth                = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    minHeight               = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    maxWidth                = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    maxHeight               = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    is3D                    = T.nullable(T.bool_query()),
    seriesStatus            = T.nullable(T.string({ max = 128, not_match = "[\\x00-\\x1f]" })),
    nameStartsWithOrGreater = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    nameStartsWith          = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    nameLessThan            = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    studioIds               = T.nullable(T.string({ max = 8192, not_match = "[\\x00-\\x1f]" })),
    genreIds                = T.nullable(T.string({ max = 8192, not_match = "[\\x00-\\x1f]" })),
    enableTotalRecordCount  = T.nullable(T.bool_query()),
    enableImages            = T.nullable(T.bool_query()),
  }
  if include_user_id then
    q.userId = T.nullable(jf_id())
  end
  return q
end

-- MediaInfoController's [ParameterObsolete] query params, shared by GET and
-- POST /Items/{itemId}/PlaybackInfo (see "items playbackinfo" below).
local function jf_playbackinfo_query()
  return T.object({
    userId               = T.nullable(jf_id()),
    maxStreamingBitrate  = T.nullable(T.number_query({ integer = true, min = 0 })),
    startTimeTicks       = T.nullable(T.number_query({ integer = true, min = 0 })),
    audioStreamIndex     = T.nullable(T.number_query({ integer = true })),
    subtitleStreamIndex  = T.nullable(T.number_query({ integer = true })),
    maxAudioChannels     = T.nullable(T.number_query({ integer = true, min = 0 })),
    mediaSourceId        = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    liveStreamId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    autoOpenLiveStream   = T.nullable(T.bool_query()),
    enableDirectPlay     = T.nullable(T.bool_query()),
    enableDirectStream   = T.nullable(T.bool_query()),
    enableTranscoding    = T.nullable(T.bool_query()),
    allowVideoStreamCopy = T.nullable(T.bool_query()),
    allowAudioStreamCopy = T.nullable(T.bool_query()),
  })
end

-- PlaybackInfoDto (Jellyfin.Api.Models.MediaInfoDtos) - GetPostedPlaybackInfo's
-- body. Every field typed except .DeviceProfile (MediaBrowser.Model.Dlna.
-- DeviceProfile - one of the largest DTOs in the whole API: DirectPlay/
-- Transcoding/Container/Codec/ResponseProfiles, each an array of further
-- nested condition objects, sent in full by every real client on every
-- playback start) - T.any() there so the key itself is still declared and
-- every other field stays strictly typed, rather than this file's older
-- "give up on the whole body" fallback for oversized DTOs.
local function jf_playback_info_dto()
  return T.object({
    UserId               = T.nullable(jf_id()),
    MaxStreamingBitrate  = T.nullable(T.number({ integer = true, min = 0 })),
    StartTimeTicks       = T.nullable(T.number({ integer = true, min = 0 })),
    AudioStreamIndex     = T.nullable(T.number({ integer = true })),
    SubtitleStreamIndex  = T.nullable(T.number({ integer = true })),
    MaxAudioChannels     = T.nullable(T.number({ integer = true, min = 0 })),
    MediaSourceId        = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    LiveStreamId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    DeviceProfile        = T.any(),
    EnableDirectPlay     = T.nullable(T.boolean()),
    EnableDirectStream   = T.nullable(T.boolean()),
    EnableTranscoding    = T.nullable(T.boolean()),
    AllowVideoStreamCopy = T.nullable(T.boolean()),
    AllowAudioStreamCopy = T.nullable(T.boolean()),
    AutoOpenLiveStream   = T.nullable(T.boolean()),
    AlwaysBurnInSubtitleWhenTranscoding = T.nullable(T.boolean()),
  })
end

-- EncodingHelper's own validation regexes for the {container}/audioCodec/
-- videoCodec/subtitleCodec query&path values and the {level} encoder-profile
-- value - reused verbatim (already the pattern this file uses for the
-- {container} path segment in "videos stream container"/"hls segment legacy").
local CONTAINER_RE = [[[a-zA-Z0-9\-._,|]{0,40}]]
local LEVEL_RE     = [[-?[0-9]+(?:\.[0-9]+)?]]

-- AudioController.GetAudioStream / VideosController.GetVideoStream: near-
-- identical [FromQuery] transcoding-parameter sets (confirmed by diffing
-- both signatures) - video adds maxWidth/maxHeight, audio doesn't. Neither
-- controller ever binds a `streamOptions` dictionary from a real client (no
-- reference in the web client source), so it's deliberately not in the
-- allowed-key set below - a request that did send it would be denied, same
-- as any other genuinely unused parameter.
local function jf_stream_query(is_video)
  local q = {
    container             = T.nullable(T.string({ max = 40, match = "^" .. CONTAINER_RE .. "$" })),
    ["static"]            = T.nullable(T.bool_query()),
    params                = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
    tag                   = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    playSessionId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    segmentContainer      = T.nullable(T.string({ max = 40, match = "^" .. CONTAINER_RE .. "$" })),
    segmentLength         = T.nullable(T.number_query({ integer = true, min = 0 })),
    minSegments           = T.nullable(T.number_query({ integer = true, min = 0 })),
    mediaSourceId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    deviceId               = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    audioCodec            = T.nullable(T.string({ max = 40, match = "^" .. CONTAINER_RE .. "$" })),
    enableAutoStreamCopy  = T.nullable(T.bool_query()),
    allowVideoStreamCopy  = T.nullable(T.bool_query()),
    allowAudioStreamCopy  = T.nullable(T.bool_query()),
    breakOnNonKeyFrames   = T.nullable(T.bool_query()),
    audioSampleRate       = T.nullable(T.number_query({ integer = true, min = 0 })),
    maxAudioBitDepth      = T.nullable(T.number_query({ integer = true, min = 0 })),
    audioBitRate          = T.nullable(T.number_query({ integer = true, min = 0 })),
    audioChannels         = T.nullable(T.number_query({ integer = true, min = 0 })),
    maxAudioChannels      = T.nullable(T.number_query({ integer = true, min = 0 })),
    profile               = T.nullable(T.string({ max = 128, not_match = "[\\x00-\\x1f]" })),
    level                 = T.nullable(T.string({ max = 32, match = "^" .. LEVEL_RE .. "$" })),
    framerate             = T.nullable(T.number_query({ min = 0 })),
    maxFramerate          = T.nullable(T.number_query({ min = 0 })),
    copyTimestamps        = T.nullable(T.bool_query()),
    startTimeTicks        = T.nullable(T.number_query({ integer = true, min = 0 })),
    width                 = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    height                = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    videoBitRate          = T.nullable(T.number_query({ integer = true, min = 0 })),
    subtitleStreamIndex   = T.nullable(T.number_query({ integer = true })),
    subtitleMethod        = T.nullable(T.string({ max = 16,
      enum = { Encode=true, Embed=true, External=true, Hls=true, Drop=true } })),
    maxRefFrames          = T.nullable(T.number_query({ integer = true, min = 0 })),
    maxVideoBitDepth      = T.nullable(T.number_query({ integer = true, min = 0 })),
    requireAvc            = T.nullable(T.bool_query()),
    deInterlace           = T.nullable(T.bool_query()),
    requireNonAnamorphic  = T.nullable(T.bool_query()),
    transcodingMaxAudioChannels = T.nullable(T.number_query({ integer = true, min = 0 })),
    cpuCoreLimit          = T.nullable(T.number_query({ integer = true, min = 0 })),
    liveStreamId          = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    enableMpegtsM2TsMode  = T.nullable(T.bool_query()),
    videoCodec            = T.nullable(T.string({ max = 40, match = "^" .. CONTAINER_RE .. "$" })),
    subtitleCodec         = T.nullable(T.string({ max = 40, match = "^" .. CONTAINER_RE .. "$" })),
    transcodeReasons      = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
    audioStreamIndex      = T.nullable(T.number_query({ integer = true })),
    videoStreamIndex      = T.nullable(T.number_query({ integer = true })),
    context               = T.nullable(T.string({ max = 16, enum = { Streaming=true, ["Static"]=true } })),
    enableAudioVbrEncoding = T.nullable(T.bool_query()),
    -- Obsolete but still bound server-side; kept accepted rather than denied.
    deviceProfileId       = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  }
  if is_video then
    q.maxWidth  = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 }))
    q.maxHeight = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 }))
  end
  return T.object(q)
end

-- QueueItem (MediaBrowser.Model.Session) - PlaybackProgressInfo/StopInfo's
-- NowPlayingQueue element.
local jf_queue_item = T.object({
  Id             = T.nullable(jf_id()),
  PlaylistItemId = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
})

-- PlaystateController's ReportPlaybackStart/Progress/Stopped
-- (PlaybackStartInfo : PlaybackProgressInfo, and the separate but
-- structurally-overlapping PlaybackStopInfo). All three real client calls
-- (playbackmanager.js's reportPlayback()) send `Object.assign({}, state.
-- PlayState)` plus a couple of call-specific fields - the *same* PlayState
-- blob every time, regardless of which of the three C# DTOs actually
-- declares which property. Confirmed by reading state.PlayState's own
-- assignments (playbackmanager.js ~line 2170-2200): it carries several
-- fields with NO C# model equivalent at all (ShuffleMode, MaxStreamingBitrate,
-- PlaybackRate, SecondarySubtitleStreamIndex, BufferedRanges) - harmless
-- server-side since System.Text.Json silently ignores unrecognized
-- properties by default, but a guaranteed false positive on every single
-- playback-progress report if this schema didn't also accept them (this
-- would have been the single most damaging gap in the whole file - these
-- three endpoints fire continuously during normal playback).
-- opts.event_name / opts.stop_only add the two fields that are genuinely
-- call-specific (EventName is progressEventName, only ever passed to
-- reportPlaybackProgress; Failed/NextMediaType only make sense on stop).
local function jf_playback_report_fields(opts)
  opts = opts or {}
  local f = {
    -- Real MediaBrowser.Model.Session.PlaybackProgressInfo/StopInfo fields.
    ItemId               = T.nullable(jf_id()),
    -- .Item (BaseItemDto) - T.any(); the bundled web client never actually
    -- populates it on these calls (only ItemId is set - see reportPlayback()
    -- in playbackmanager.js), but accepted defensively for any other real
    -- client that might.
    Item                 = T.any(),
    SessionId            = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    MediaSourceId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    AudioStreamIndex      = T.nullable(T.number({ integer = true })),
    SubtitleStreamIndex   = T.nullable(T.number({ integer = true })),
    CanSeek               = T.nullable(T.boolean()),
    IsPaused              = T.nullable(T.boolean()),
    IsMuted               = T.nullable(T.boolean()),
    PositionTicks         = T.nullable(T.number({ integer = true, min = 0 })),
    PlaybackStartTimeTicks = T.nullable(T.number({ integer = true, min = 0 })),
    VolumeLevel           = T.nullable(T.number({ integer = true, min = 0, max = 100 })),
    Brightness            = T.nullable(T.number({ integer = true })),
    AspectRatio           = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
    PlayMethod            = T.nullable(T.string({ max = 16, enum = { Transcode=true, DirectStream=true, DirectPlay=true } })),
    LiveStreamId          = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    PlaySessionId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    RepeatMode            = T.nullable(T.string({ max = 16, enum = { RepeatNone=true, RepeatAll=true, RepeatOne=true } })),
    PlaybackOrder         = T.nullable(T.string({ max = 16, enum = { Default=true, Shuffle=true } })),
    NowPlayingQueue       = T.nullable(T.array(jf_queue_item, { max = 8192 })),
    PlaylistItemId        = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    -- Client-only, no C# model property (see the big comment above).
    ShuffleMode           = T.nullable(T.string({ max = 16, enum = { Sorted=true, Shuffle=true } })),
    MaxStreamingBitrate   = T.nullable(T.number({ integer = true, min = 0 })),
    PlaybackRate          = T.nullable(T.number({ min = 0 })),
    SecondarySubtitleStreamIndex = T.nullable(T.number({ integer = true })),
    BufferedRanges        = T.nullable(T.array(T.object({
      start = T.nullable(T.number({ min = 0 })),
      ["end"] = T.nullable(T.number({ min = 0 })),
    }), { max = 256 })),
  }
  if opts.event_name then
    f.EventName = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" }))
  end
  if opts.stop_only then
    f.Failed         = T.nullable(T.boolean())
    f.NextMediaType   = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" }))
  end
  return f
end

-- Session/device/playlist-entry/timer IDs: opaque server-generated tokens,
-- not necessarily GUID-shaped (SessionController/PlaylistsController/
-- LiveTvController all bind these as plain `string`, not `Guid`).
local OPAQUE_ID = "[0-9A-Za-z_.-]+"

-- PlaystateCommand enum (MediaBrowser.Model.Session.PlaystateCommand)
local PLAYSTATE_COMMAND = "(?:Stop|Pause|Unpause|NextTrack|PreviousTrack|Seek|Rewind|FastForward|PlayPause)"

-- PlayCommand enum (MediaBrowser.Model.Session.PlayCommand)
local PLAY_COMMAND_ENUM = { PlayNow=true, PlayNext=true, PlayLast=true, PlayInstantMix=true, PlayShuffle=true }

-- BaseItemKind enum (MediaBrowser.Model.Entities.BaseItemKind) - used by
-- SessionController's DisplayContent (?itemType=, required).
local BASE_ITEM_KIND_ENUM = {}
for _, v in ipairs({
  "AggregateFolder","Audio","AudioBook","BasePluginFolder","Book","BoxSet","Channel",
  "ChannelFolderItem","CollectionFolder","Episode","Folder","Genre","ManualPlaylistsFolder",
  "Movie","LiveTvChannel","LiveTvProgram","MusicAlbum","MusicArtist","MusicGenre","MusicVideo",
  "Person","Photo","PhotoAlbum","Playlist","PlaylistsFolder","Program","Recording","Season",
  "Series","Studio","Trailer","TvChannel","TvProgram","UserRootFolder","UserView","Video","Year",
}) do BASE_ITEM_KIND_ENUM[v] = true end

-- GeneralCommandType enum (MediaBrowser.Model.Session.GeneralCommandType) -
-- both a T.string enum table (body/query fields) and a path-regex
-- alternation (Sessions/{id}/System|Command/{command} path segments).
local GENERAL_COMMAND_LIST = {
  "MoveUp","MoveDown","MoveLeft","MoveRight","PageUp","PageDown","PreviousLetter","NextLetter",
  "ToggleOsd","ToggleContextMenu","Select","Back","TakeScreenshot","SendKey","SendString",
  "GoHome","GoToSettings","VolumeUp","VolumeDown","Mute","Unmute","ToggleMute","SetVolume",
  "SetAudioStreamIndex","SetSubtitleStreamIndex","ToggleFullscreen","DisplayContent","GoToSearch",
  "DisplayMessage","SetRepeatMode","ChannelUp","ChannelDown","Guide","ToggleStats",
  "PlayMediaSource","PlayTrailers","SetShuffleQueue","PlayState","PlayNext","ToggleOsdMenu",
  "Play","SetMaxStreamingBitrate","SetPlaybackOrder",
}
local GENERAL_COMMAND_ENUM = {}
for _, v in ipairs(GENERAL_COMMAND_LIST) do GENERAL_COMMAND_ENUM[v] = true end
local GENERAL_COMMAND_ALT = "(?:" .. table.concat(GENERAL_COMMAND_LIST, "|") .. ")"


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
-- LibraryStructureController DTOs (MediaBrowser.Model.Configuration.*)
-- Shared by "lib virtual" (POST body: AddVirtualFolderDto), "lib virtual
-- library options" (POST body: UpdateLibraryOptionsDto) - both nest the same
-- LibraryOptions object. Confirmed live: JsonDefaults.cs registers a global
-- JsonStringEnumConverter, so every enum here (ImageType, the obsolete-but-
-- still-wire-valid EmbeddedSubtitleOptions) round-trips as its C# member
-- name string, not the underlying int. No field in LibraryOptions.cs carries
-- [Required]/`required` - all nullable, since a client may PATCH just a
-- subset when updating an existing library's options.
-- ---------------------------------------------------------------------------

local IMAGE_TYPE_ENUM = { Primary=true, Art=true, Backdrop=true, Banner=true, Logo=true, Thumb=true,
  Disc=true, Box=true, Screenshot=true, Menu=true, Chapter=true, BoxRear=true, Profile=true }

-- Same 13 values as IMAGE_TYPE_ENUM, as a path-regex alternation - used by
-- ImageController's GET/HEAD/POST/DELETE {imageType} path segment routes,
-- which previously only covered Thumb/Logo/Primary/Backdrop individually
-- (a real gap: Art/Disc/Box/Screenshot/Menu/Chapter/BoxRear/Profile were
-- all "no route matched", found via a full ImageController audit against
-- real source, not a live false-positive report like tonight's other fixes).
local IMAGE_TYPE_ALT = "(?:Primary|Art|Backdrop|Banner|Logo|Thumb|Disc|Box|Screenshot|Menu|Chapter|BoxRear|Profile)"

-- ImageFormat enum (MediaBrowser.Model.Drawing.ImageFormat) - query param
-- on every image GET, not a JSON body field, so JsonStringEnumConverter
-- doesn't apply; kept case-sensitive/canonical to match this file's
-- existing convention for path-segment enums (see IMAGE_TYPE_ALT above).
local IMAGE_FORMAT_ENUM = { Bmp=true, Gif=true, Jpg=true, Png=true, Webp=true, Svg=true }

-- Valid upload Content-Types (ImageController.TryGetImageExtensionFromContentType,
-- confirmed via its own xunit test data) - used by every image-upload POST route.
local IMAGE_CONTENT_TYPES = {
  "image/apng", "image/avif", "image/bmp", "image/gif", "image/x-icon",
  "image/jpeg", "image/png", "image/svg+xml", "image/tiff", "image/webp",
}

-- Shared query schema for every image GET/HEAD endpoint (Items/Artists/
-- Genres/MusicGenres/Persons/Studios/Users all bind the identical parameter
-- set via GetImageInternal - confirmed by diffing GetItemImage/
-- GetArtistImage/GetGenreImage/etc.'s signatures, all match).
local function jf_image_query()
  return T.object({
    maxWidth        = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    maxHeight       = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    width           = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    height          = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    quality         = T.nullable(T.number_query({ integer = true, min = 0, max = 100 })),
    fillWidth       = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    fillHeight      = T.nullable(T.number_query({ integer = true, min = 0, max = 100000 })),
    tag             = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    format          = T.nullable(T.string({ max = 8, enum = IMAGE_FORMAT_ENUM })),
    percentPlayed   = T.nullable(T.number_query({ min = 0, max = 100 })),
    unplayedCount   = T.nullable(T.number_query({ integer = true, min = 0 })),
    blur            = T.nullable(T.number_query({ integer = true, min = 0, max = 100 })),
    backgroundColor = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
    foregroundLayer = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
    imageIndex      = T.nullable(T.number_query({ integer = true, min = 0, max = 999 })),
  })
end

local jf_image_option = T.object({
  Type     = T.nullable(T.string({ max = 16, enum = IMAGE_TYPE_ENUM })),
  Limit    = T.nullable(T.number({ integer = true, min = 0, max = 100 })),
  MinWidth = T.nullable(T.number({ integer = true, min = 0, max = 100000 })),
})

-- Plugin/provider name lists (MetadataFetchers, ImageFetchers, ...): plugin
-- names are config/install-dependent, not a fixed enum this WAF can know in
-- advance - bounded generic strings, same posture as mediawiki's
-- dynamic_type_expr fields.
local function jf_provider_list()
  return T.nullable(T.array(T.string({ max = 128, not_match = "[\\x00-\\x1f]" }), { max = 64 }))
end

local jf_type_options = T.object({
  Type                 = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  MetadataFetchers      = jf_provider_list(),
  MetadataFetcherOrder  = jf_provider_list(),
  ImageFetchers         = jf_provider_list(),
  ImageFetcherOrder     = jf_provider_list(),
  ImageOptions          = T.nullable(T.array(jf_image_option, { max = 32 })),
})

local jf_media_path_info = T.object({
  Path = T.string({ max = 4096, not_match = "[\\x00-\\x1f]" }),
}, { required = { Path = true } })

local jf_library_options = T.object({
  Enabled                              = T.nullable(T.boolean()),
  -- Sent by the web client (libraryoptionseditor.js) but absent from this
  -- server checkout's LibraryOptions.cs - confirmed live (real deny log)
  -- that the deployed server accepts it; client/server versions have
  -- drifted apart on this one field. Cross-reference the web client
  -- directly, not just the C# model, for any future LibraryOptions field.
  EnableArchiveMediaFiles              = T.nullable(T.boolean()),
  EnablePhotos                         = T.nullable(T.boolean()),
  EnableRealtimeMonitor                = T.nullable(T.boolean()),
  EnableLUFSScan                       = T.nullable(T.boolean()),
  EnableChapterImageExtraction         = T.nullable(T.boolean()),
  ExtractChapterImagesDuringLibraryScan  = T.nullable(T.boolean()),
  EnableTrickplayImageExtraction       = T.nullable(T.boolean()),
  ExtractTrickplayImagesDuringLibraryScan = T.nullable(T.boolean()),
  PathInfos                            = T.nullable(T.array(jf_media_path_info, { max = 64 })),
  SaveLocalMetadata                    = T.nullable(T.boolean()),
  EnableInternetProviders              = T.nullable(T.boolean()),  -- [Obsolete] but still deserialized
  EnableAutomaticSeriesGrouping        = T.nullable(T.boolean()),
  EnableEmbeddedTitles                 = T.nullable(T.boolean()),
  EnableEmbeddedExtrasTitles           = T.nullable(T.boolean()),
  EnableEmbeddedEpisodeInfos           = T.nullable(T.boolean()),
  AutomaticRefreshIntervalDays         = T.nullable(T.number({ integer = true, min = 0, max = 3650 })),
  PreferredMetadataLanguage            = T.nullable(T.string({ max = 16, not_match = "[\\x00-\\x1f]" })),
  MetadataCountryCode                  = T.nullable(T.string({ max = 8, not_match = "[\\x00-\\x1f]" })),
  SeasonZeroDisplayName                = T.nullable(T.string({ max = 128, not_match = "[\\x00-\\x1f]" })),
  MetadataSavers                       = jf_provider_list(),
  DisabledLocalMetadataReaders         = jf_provider_list(),
  LocalMetadataReaderOrder             = jf_provider_list(),
  DisabledSubtitleFetchers             = jf_provider_list(),
  SubtitleFetcherOrder                 = jf_provider_list(),
  DisabledMediaSegmentProviders        = jf_provider_list(),
  MediaSegmentProviderOrder            = jf_provider_list(),
  SkipSubtitlesIfEmbeddedSubtitlesPresent = T.nullable(T.boolean()),
  SkipSubtitlesIfAudioTrackMatches     = T.nullable(T.boolean()),
  SubtitleDownloadLanguages            = jf_provider_list(),
  RequirePerfectSubtitleMatch          = T.nullable(T.boolean()),
  SaveSubtitlesWithMedia               = T.nullable(T.boolean()),
  SaveLyricsWithMedia                  = T.nullable(T.boolean()),
  SaveTrickplayWithMedia               = T.nullable(T.boolean()),
  DisabledLyricFetchers                = jf_provider_list(),
  LyricFetcherOrder                    = jf_provider_list(),
  PreferNonstandardArtistsTag          = T.nullable(T.boolean()),
  UseCustomTagDelimiters               = T.nullable(T.boolean()),
  CustomTagDelimiters                  = T.nullable(T.array(T.string({ max = 4 }), { max = 16 })),
  DelimiterWhitelist                   = jf_provider_list(),
  AutomaticallyAddToCollection         = T.nullable(T.boolean()),
  AllowEmbeddedSubtitles               = T.nullable(T.string({ max = 16,
    enum = { AllowAll=true, AllowText=true, AllowImage=true, AllowNone=true } })),
  TypeOptions                          = T.nullable(T.array(jf_type_options, { max = 32 })),
})

-- ---------------------------------------------------------------------------
-- ServerConfiguration (ConfigurationController's GET/POST /System/Configuration)
-- and its nested types. All fields nullable/optional: UpdateConfiguration binds
-- a plain POCO with C#-side defaults, not a partial-patch DTO with [Required]
-- members, so a client may omit anything and the server fills its own default.
-- ---------------------------------------------------------------------------

-- RepositoryInfo (MediaBrowser.Model.Updates) - also the top-level array body
-- of PackageController's POST /Repositories.
local jf_repository_info = T.object({
  Name    = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  Url     = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
  Enabled = T.nullable(T.boolean()),
})

-- MetadataOptions (MediaBrowser.Model.Configuration)
local jf_metadata_options = T.object({
  ItemType                 = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  DisabledMetadataSavers   = jf_provider_list(),
  LocalMetadataReaderOrder = jf_provider_list(),
  DisabledMetadataFetchers = jf_provider_list(),
  MetadataFetcherOrder     = jf_provider_list(),
  DisabledImageFetchers    = jf_provider_list(),
  ImageFetcherOrder        = jf_provider_list(),
})

-- PathSubstitution (MediaBrowser.Model.Configuration)
local jf_path_substitution = T.object({
  From = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
  To   = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
})

-- NameValuePair (MediaBrowser.Model.Dto)
local jf_name_value_pair = T.object({
  Name  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  Value = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
})

-- CastReceiverApplication (MediaBrowser.Model.System) - Id/Name are `required`
-- string members in C#, but System.Text.Json's `required` only enforces
-- presence at deserialize time for the top-level UpdateConfiguration bind,
-- which we're not replicating key-by-key here; keep both required to match
-- the C# contract as closely as this DSL allows.
local jf_cast_receiver_application = T.object({
  Id   = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }),
  Name = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }),
}, { required = { Id = true, Name = true } })

-- TrickplayOptions (MediaBrowser.Model.Configuration) - TrickplayScanBehavior
-- and ProcessPriorityClass are both bound through the global
-- JsonStringEnumConverter (JsonDefaults.cs), so string enum names, not ints.
local jf_trickplay_options = T.object({
  EnableHwAcceleration        = T.nullable(T.boolean()),
  EnableHwEncoding            = T.nullable(T.boolean()),
  EnableKeyFrameOnlyExtraction = T.nullable(T.boolean()),
  ScanBehavior                = T.nullable(T.string({ max = 16,
    enum = { Blocking=true, NonBlocking=true } })),
  ProcessPriority             = T.nullable(T.string({ max = 16,
    enum = { Normal=true, Idle=true, High=true, RealTime=true, BelowNormal=true, AboveNormal=true } })),
  Interval          = T.nullable(T.number({ integer = true, min = 0 })),
  WidthResolutions  = T.nullable(T.array(T.number({ integer = true, min = 1, max = 100000 }), { max = 16 })),
  TileWidth         = T.nullable(T.number({ integer = true, min = 1, max = 100 })),
  TileHeight        = T.nullable(T.number({ integer = true, min = 1, max = 100 })),
  Qscale            = T.nullable(T.number({ integer = true, min = 0, max = 100 })),
  JpegQuality       = T.nullable(T.number({ integer = true, min = 0, max = 100 })),
  ProcessThreads    = T.nullable(T.number({ integer = true, min = 1, max = 256 })),
})

local jf_server_configuration = T.object({
  -- BaseApplicationConfiguration
  LogFileRetentionDays     = T.nullable(T.number({ integer = true, min = 0, max = 3650 })),
  IsStartupWizardCompleted = T.nullable(T.boolean()),
  CachePath                = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
  PreviousVersionStr       = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
  -- ServerConfiguration
  EnableMetrics                       = T.nullable(T.boolean()),
  EnableNormalizedItemByNameIds       = T.nullable(T.boolean()),
  IsPortAuthorized                    = T.nullable(T.boolean()),
  QuickConnectAvailable               = T.nullable(T.boolean()),
  EnableCaseSensitiveItemIds          = T.nullable(T.boolean()),
  DisableLiveTvChannelUserDataName    = T.nullable(T.boolean()),
  MetadataPath              = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
  PreferredMetadataLanguage = T.nullable(T.string({ max = 16, not_match = "[\\x00-\\x1f]" })),
  MetadataCountryCode       = T.nullable(T.string({ max = 8, not_match = "[\\x00-\\x1f]" })),
  SortReplaceCharacters     = T.nullable(T.array(T.string({ max = 8 }), { max = 64 })),
  SortRemoveCharacters      = T.nullable(T.array(T.string({ max = 8 }), { max = 64 })),
  SortRemoveWords           = T.nullable(T.array(T.string({ max = 64 }), { max = 256 })),
  MinResumePct              = T.nullable(T.number({ integer = true, min = 0, max = 100 })),
  MaxResumePct              = T.nullable(T.number({ integer = true, min = 0, max = 100 })),
  MinResumeDurationSeconds  = T.nullable(T.number({ integer = true, min = 0 })),
  MinAudiobookResume        = T.nullable(T.number({ integer = true, min = 0 })),
  MaxAudiobookResume        = T.nullable(T.number({ integer = true, min = 0 })),
  InactiveSessionThreshold  = T.nullable(T.number({ integer = true, min = 0 })),
  LibraryMonitorDelay       = T.nullable(T.number({ integer = true, min = 0 })),
  LibraryUpdateDuration     = T.nullable(T.number({ integer = true, min = 0 })),
  CacheSize                 = T.nullable(T.number({ integer = true, min = 0 })),
  ImageSavingConvention     = T.nullable(T.string({ max = 16, enum = { Legacy=true, Compatible=true } })),
  MetadataOptions           = T.nullable(T.array(jf_metadata_options, { max = 64 })),
  SkipDeserializationForBasicTypes = T.nullable(T.boolean()),
  ServerName                = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  UICulture                 = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
  SaveMetadataHidden        = T.nullable(T.boolean()),
  ContentTypes              = T.nullable(T.array(jf_name_value_pair, { max = 128 })),
  RemoteClientBitrateLimit  = T.nullable(T.number({ integer = true, min = 0 })),
  EnableFolderView                  = T.nullable(T.boolean()),
  EnableGroupingMoviesIntoCollections = T.nullable(T.boolean()),
  EnableGroupingShowsIntoCollections = T.nullable(T.boolean()),
  DisplaySpecialsWithinSeasons      = T.nullable(T.boolean()),
  CodecsUsed                = T.nullable(T.array(T.string({ max = 32 }), { max = 128 })),
  PluginRepositories        = T.nullable(T.array(jf_repository_info, { max = 64 })),
  EnableExternalContentInSuggestions = T.nullable(T.boolean()),
  ImageExtractionTimeoutMs  = T.nullable(T.number({ integer = true, min = 0 })),
  PathSubstitutions         = T.nullable(T.array(jf_path_substitution, { max = 128 })),
  EnableSlowResponseWarning = T.nullable(T.boolean()),
  SlowResponseThresholdMs   = T.nullable(T.number({ integer = true, min = 0 })),
  CorsHosts                 = T.nullable(T.array(T.string({ max = 512 }), { max = 64 })),
  ActivityLogRetentionDays  = T.nullable(T.number({ integer = true, min = 0, max = 36500 })),
  LibraryScanFanoutConcurrency        = T.nullable(T.number({ integer = true, min = 0 })),
  LibraryMetadataRefreshConcurrency   = T.nullable(T.number({ integer = true, min = 0 })),
  AllowClientLogUpload       = T.nullable(T.boolean()),
  DummyChapterDuration       = T.nullable(T.number({ integer = true })),
  ChapterImageResolution     = T.nullable(T.string({ max = 16,
    enum = { MatchSource=true, P144=true, P240=true, P360=true, P480=true, P720=true, P1080=true, P1440=true, P2160=true } })),
  ParallelImageEncodingLimit = T.nullable(T.number({ integer = true, min = 0 })),
  CastReceiverApplications   = T.nullable(T.array(jf_cast_receiver_application, { max = 64 })),
  TrickplayOptions           = T.nullable(jf_trickplay_options),
  EnableLegacyAuthorization  = T.nullable(T.boolean()),
})

-- ---------------------------------------------------------------------------
-- UserController DTOs (UserDto/UserConfiguration/UserPolicy and friends).
-- ---------------------------------------------------------------------------

-- UserConfiguration (MediaBrowser.Model.Configuration) - all fields optional,
-- none [Required]; a client may PATCH-by-omission (see "users configuration").
local jf_user_configuration = T.object({
  AudioLanguagePreference    = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
  PlayDefaultAudioTrack      = T.nullable(T.boolean()),
  SubtitleLanguagePreference = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
  DisplayMissingEpisodes     = T.nullable(T.boolean()),
  GroupedFolders             = T.nullable(T.array(jf_id(), { max = 4096 })),
  SubtitleMode               = T.nullable(T.string({ max = 16,
    enum = { Default=true, Always=true, OnlyForced=true, None=true, Smart=true } })),
  DisplayCollectionsView     = T.nullable(T.boolean()),
  EnableLocalPassword        = T.nullable(T.boolean()),
  OrderedViews               = T.nullable(T.array(jf_id(), { max = 4096 })),
  LatestItemsExcludes        = T.nullable(T.array(jf_id(), { max = 4096 })),
  MyMediaExcludes            = T.nullable(T.array(jf_id(), { max = 4096 })),
  HidePlayedInLatest         = T.nullable(T.boolean()),
  RememberAudioSelections    = T.nullable(T.boolean()),
  RememberSubtitleSelections = T.nullable(T.boolean()),
  EnableNextEpisodeAutoPlay  = T.nullable(T.boolean()),
  CastReceiverId             = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
})

-- AccessSchedule (Jellyfin.Database.Implementations.Entities) - Id/UserId are
-- server-assigned (private setters); a client-supplied UserPolicy still
-- round-trips them as plain ints/guids in the JSON, so accept but don't
-- require them.
local jf_access_schedule = T.object({
  Id        = T.nullable(T.number({ integer = true })),
  UserId    = T.nullable(jf_id()),
  DayOfWeek = T.nullable(T.string({ max = 16,
    enum = { Sunday=true, Monday=true, Tuesday=true, Wednesday=true, Thursday=true,
             Friday=true, Saturday=true, Everyday=true, Weekday=true, Weekend=true } })),
  StartHour = T.nullable(T.number({ min = 0, max = 24 })),
  EndHour   = T.nullable(T.number({ min = 0, max = 24 })),
})

local UNRATED_ITEM_ENUM = { Movie=true, Trailer=true, Series=true, Music=true, Book=true,
  LiveTvChannel=true, LiveTvProgram=true, ChannelContent=true, Other=true }

-- UserPolicy (MediaBrowser.Model.Users) - all fields optional.
local jf_user_policy = T.object({
  IsAdministrator                   = T.nullable(T.boolean()),
  IsHidden                          = T.nullable(T.boolean()),
  EnableCollectionManagement        = T.nullable(T.boolean()),
  EnableSubtitleManagement          = T.nullable(T.boolean()),
  EnableLyricManagement             = T.nullable(T.boolean()),
  IsDisabled                        = T.nullable(T.boolean()),
  MaxParentalRating                 = T.nullable(T.number({ integer = true })),
  MaxParentalSubRating              = T.nullable(T.number({ integer = true })),
  BlockedTags                       = T.nullable(T.array(T.string({ max = 256 }), { max = 1024 })),
  AllowedTags                       = T.nullable(T.array(T.string({ max = 256 }), { max = 1024 })),
  EnableUserPreferenceAccess        = T.nullable(T.boolean()),
  AccessSchedules                   = T.nullable(T.array(jf_access_schedule, { max = 64 })),
  BlockUnratedItems                 = T.nullable(T.array(T.string({ max = 16, enum = UNRATED_ITEM_ENUM }), { max = 16 })),
  EnableRemoteControlOfOtherUsers   = T.nullable(T.boolean()),
  EnableSharedDeviceControl         = T.nullable(T.boolean()),
  EnableRemoteAccess                = T.nullable(T.boolean()),
  EnableLiveTvManagement            = T.nullable(T.boolean()),
  EnableLiveTvAccess                = T.nullable(T.boolean()),
  EnableMediaPlayback               = T.nullable(T.boolean()),
  EnableAudioPlaybackTranscoding    = T.nullable(T.boolean()),
  EnableVideoPlaybackTranscoding    = T.nullable(T.boolean()),
  EnablePlaybackRemuxing            = T.nullable(T.boolean()),
  ForceRemoteSourceTranscoding      = T.nullable(T.boolean()),
  EnableContentDeletion             = T.nullable(T.boolean()),
  EnableContentDeletionFromFolders  = T.nullable(T.array(T.string({ max = 4096 }), { max = 4096 })),
  EnableContentDownloading          = T.nullable(T.boolean()),
  EnableSyncTranscoding             = T.nullable(T.boolean()),
  EnableMediaConversion             = T.nullable(T.boolean()),
  EnabledDevices                    = T.nullable(T.array(T.string({ max = 256 }), { max = 4096 })),
  EnableAllDevices                  = T.nullable(T.boolean()),
  EnabledChannels                   = T.nullable(T.array(jf_id(), { max = 4096 })),
  EnableAllChannels                 = T.nullable(T.boolean()),
  EnabledFolders                    = T.nullable(T.array(jf_id(), { max = 4096 })),
  EnableAllFolders                  = T.nullable(T.boolean()),
  InvalidLoginAttemptCount          = T.nullable(T.number({ integer = true, min = 0 })),
  LoginAttemptsBeforeLockout        = T.nullable(T.number({ integer = true })),
  MaxActiveSessions                 = T.nullable(T.number({ integer = true, min = 0 })),
  EnablePublicSharing               = T.nullable(T.boolean()),
  BlockedMediaFolders               = T.nullable(T.array(jf_id(), { max = 4096 })),
  BlockedChannels                   = T.nullable(T.array(jf_id(), { max = 4096 })),
  RemoteClientBitrateLimit          = T.nullable(T.number({ integer = true, min = 0 })),
  AuthenticationProviderId          = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
  PasswordResetProviderId           = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
  SyncPlayAccess                    = T.nullable(T.string({ max = 24,
    enum = { CreateAndJoinGroups=true, JoinGroups=true, None=true } })),
})

-- UpdateUserPassword (Jellyfin.Api.Models.UserDtos) - shared by "users
-- password" (current-form, ?userId= query) and "users password legacy"
-- ({userId} path segment).
local function jf_update_user_password()
  return T.object({
    CurrentPassword = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
    CurrentPw       = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
    NewPw           = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
    ResetPassword   = T.nullable(T.boolean()),
  })
end

-- UserDto (MediaBrowser.Model.Dto) - the "users list" POST/UpdateUser and
-- "users by id" POST/UpdateUserLegacy body. Only .Name and .Configuration are
-- actually read server-side (.Policy is ignored here - it has its own
-- dedicated "users policy" endpoint) but the whole DTO is still what a real
-- client serializes and sends, so it's all validated.
local jf_user_dto = T.object({
  Name                    = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  ServerId                = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  ServerName              = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  Id                      = T.nullable(jf_id()),
  PrimaryImageTag         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  HasPassword             = T.nullable(T.boolean()),
  HasConfiguredPassword   = T.nullable(T.boolean()),
  HasConfiguredEasyPassword = T.nullable(T.boolean()),
  EnableAutoLogin         = T.nullable(T.boolean()),
  LastLoginDate           = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  LastActivityDate        = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  Configuration           = T.nullable(jf_user_configuration),
  Policy                  = T.nullable(jf_user_policy),
  PrimaryImageAspectRatio = T.nullable(T.number()),
})

-- ---------------------------------------------------------------------------
-- LiveTvController DTOs - TimerInfoDto/SeriesTimerInfoDto (DVR timer CRUD).
-- ---------------------------------------------------------------------------

local DAY_OF_WEEK_ENUM = { Sunday=true, Monday=true, Tuesday=true, Wednesday=true,
  Thursday=true, Friday=true, Saturday=true }

-- BaseTimerInfoDto (MediaBrowser.Model.LiveTv) fields shared by
-- TimerInfoDto/SeriesTimerInfoDto. .ProgramInfo (TimerInfoDto only) is a
-- BaseItemDto - same "genuinely huge, self-referential" exemption as
-- elsewhere in this file, so it's added separately by jf_timer_info_dto
-- rather than folded in here.
local function jf_base_timer_fields()
  return {
    Id                       = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    Type                     = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
    ServerId                 = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    ExternalId               = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    ChannelId                = T.nullable(jf_id()),
    ExternalChannelId        = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    ChannelName              = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
    ChannelPrimaryImageTag   = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    ProgramId                = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    ExternalProgramId        = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    Name                     = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
    Overview                 = T.nullable(T.string({ max = 65536, not_match = "[\\x00-\\x1f]" })),
    StartDate                = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
    EndDate                  = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
    ServiceName              = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    Priority                 = T.nullable(T.number({ integer = true })),
    PrePaddingSeconds        = T.nullable(T.number({ integer = true, min = 0 })),
    PostPaddingSeconds       = T.nullable(T.number({ integer = true, min = 0 })),
    IsPrePaddingRequired     = T.nullable(T.boolean()),
    ParentBackdropItemId     = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
    ParentBackdropImageTags  = T.nullable(T.array(T.string({ max = 256 }), { max = 32 })),
    IsPostPaddingRequired    = T.nullable(T.boolean()),
    KeepUntil                = T.nullable(T.string({ max = 24,
      enum = { UntilDeleted=true, UntilSpaceNeeded=true, UntilWatched=true, UntilDate=true } })),
  }
end

local function jf_timer_info_dto()
  local f = jf_base_timer_fields()
  f.Status                = T.nullable(T.string({ max = 24,
    enum = { New=true, InProgress=true, Completed=true, Cancelled=true,
             ConflictedOk=true, ConflictedNotOk=true, Error=true } }))
  f.SeriesTimerId          = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" }))
  f.ExternalSeriesTimerId  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" }))
  f.RunTimeTicks           = T.nullable(T.number({ integer = true, min = 0 }))
  -- .ProgramInfo: BaseItemDto - T.any() (see jf_base_item_dto's own comment
  -- further down for why; this function runs before that one is defined,
  -- so it can't reference jf_base_item_dto directly).
  f.ProgramInfo             = T.any()
  return T.object(f)
end

local function jf_series_timer_info_dto()
  local f = jf_base_timer_fields()
  f.RecordAnyTime          = T.nullable(T.boolean())
  f.SkipEpisodesInLibrary  = T.nullable(T.boolean())
  f.RecordAnyChannel       = T.nullable(T.boolean())
  f.KeepUpTo               = T.nullable(T.number({ integer = true, min = 0 }))
  f.RecordNewOnly          = T.nullable(T.boolean())
  f.Days                   = T.nullable(T.array(T.string({ max = 16, enum = DAY_OF_WEEK_ENUM }), { max = 7 }))
  f.DayPattern             = T.nullable(T.string({ max = 16, enum = { Daily=true, Weekdays=true, Weekends=true } }))
  f.ImageTags              = T.nullable(T.dict(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })))
  f.ParentThumbItemId      = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" }))
  f.ParentThumbImageTag    = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" }))
  f.ParentPrimaryImageItemId = T.nullable(jf_id())
  f.ParentPrimaryImageTag  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" }))
  return T.object(f)
end

-- TunerHostInfo (MediaBrowser.Model.LiveTv) - AddTunerHost's body.
local jf_tuner_host_info = T.object({
  Id                             = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  Url                            = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
  Type                           = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  DeviceId                       = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  FriendlyName                   = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  ImportFavoritesOnly            = T.nullable(T.boolean()),
  AllowHWTranscoding             = T.nullable(T.boolean()),
  AllowFmp4TranscodingContainer  = T.nullable(T.boolean()),
  AllowStreamSharing             = T.nullable(T.boolean()),
  FallbackMaxStreamingBitrate    = T.nullable(T.number({ integer = true, min = 0 })),
  EnableStreamLooping            = T.nullable(T.boolean()),
  Source                         = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  TunerCount                     = T.nullable(T.number({ integer = true, min = 0 })),
  UserAgent                      = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
  IgnoreDts                      = T.nullable(T.boolean()),
  ReadAtNativeFramerate          = T.nullable(T.boolean()),
})

-- ---------------------------------------------------------------------------
-- BaseItemDto (MediaBrowser.Model.Dto) - ItemUpdateController.UpdateItem's
-- body ("items by id update") and the .Item/.ProgramInfo field embedded in
-- several other DTOs elsewhere in this file. ~140 of its ~150 fields are
-- flat scalars or small nested types (typed exactly below, via the small
-- helper types just after this comment); only MediaSources (MediaSourceInfo[]),
-- MediaStreams (MediaStream[]) and the self-referential CurrentProgram
-- (BaseItemDto) are genuinely large/recursive enough that typing them out
-- would mean re-deriving this same effort for MediaSourceInfo/MediaStream's
-- own dozens of transcoding-profile fields - those three use T.any() so the
-- *key* is still declared (no false positive if a real client sends it) but
-- its contents aren't inspected, which is strictly better than this file's
-- older "give up on the whole body" fallback for oversized DTOs.
-- ---------------------------------------------------------------------------

local jf_name_guid_pair = T.object({
  Name = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  Id   = T.nullable(jf_id()),
})

local jf_base_item_person = T.object({
  Name             = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  Id               = T.nullable(jf_id()),
  Role             = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  Type             = T.nullable(T.string({ max = 24, enum = {
    Unknown=true, Actor=true, Director=true, Composer=true, Writer=true, GuestStar=true,
    Producer=true, Conductor=true, Lyricist=true, Arranger=true, Engineer=true, Mixer=true,
    Remixer=true, Creator=true, Artist=true, AlbumArtist=true, Author=true, Illustrator=true,
    Penciller=true, Inker=true, Colorist=true, Letterer=true, CoverArtist=true, Editor=true,
    Translator=true } })),
  PrimaryImageTag  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  ImageBlurHashes  = T.nullable(T.dict(T.dict(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })))),
})

local jf_external_url = T.object({
  Name = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  Url  = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
})

local jf_media_url = T.object({
  Url  = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
  Name = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
})

local jf_chapter_info = T.object({
  StartPositionTicks = T.nullable(T.number({ integer = true, min = 0 })),
  Name               = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  ImagePath          = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
  ImageDateModified  = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  ImageTag           = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
})

local jf_trickplay_info_dto = T.object({
  Width          = T.nullable(T.number({ integer = true, min = 0 })),
  Height         = T.nullable(T.number({ integer = true, min = 0 })),
  TileWidth      = T.nullable(T.number({ integer = true, min = 0 })),
  TileHeight     = T.nullable(T.number({ integer = true, min = 0 })),
  ThumbnailCount = T.nullable(T.number({ integer = true, min = 0 })),
  Interval       = T.nullable(T.number({ integer = true, min = 0 })),
  Bandwidth      = T.nullable(T.number({ integer = true, min = 0 })),
})

local jf_base_item_dto
jf_base_item_dto = T.object({
  Name                     = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  OriginalTitle            = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  ServerId                 = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  Id                       = T.nullable(jf_id()),
  Etag                     = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  SourceType               = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
  PlaylistItemId           = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  DateCreated              = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  DateLastMediaAdded       = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  ExtraType                = T.nullable(T.string({ max = 24, enum = {
    Unknown=true, Clip=true, Trailer=true, BehindTheScenes=true, DeletedScene=true,
    Interview=true, Scene=true, Sample=true, ThemeSong=true, ThemeVideo=true,
    Featurette=true, Short=true } })),
  AirsBeforeSeasonNumber   = T.nullable(T.number({ integer = true })),
  AirsAfterSeasonNumber    = T.nullable(T.number({ integer = true })),
  AirsBeforeEpisodeNumber  = T.nullable(T.number({ integer = true })),
  CanDelete                = T.nullable(T.boolean()),
  CanDownload              = T.nullable(T.boolean()),
  HasLyrics                = T.nullable(T.boolean()),
  HasSubtitles             = T.nullable(T.boolean()),
  PreferredMetadataLanguage    = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
  PreferredMetadataCountryCode = T.nullable(T.string({ max = 8, not_match = "[\\x00-\\x1f]" })),
  Container                = T.nullable(T.string({ max = 128, not_match = "[\\x00-\\x1f]" })),
  SortName                 = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  ForcedSortName            = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  Video3DFormat            = T.nullable(T.string({ max = 24, enum = {
    HalfSideBySide=true, FullSideBySide=true, FullTopAndBottom=true, HalfTopAndBottom=true, MVC=true } })),
  PremiereDate             = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  ExternalUrls             = T.nullable(T.array(jf_external_url, { max = 64 })),
  MediaSources             = T.any(),
  CriticRating             = T.nullable(T.number()),
  ProductionLocations      = T.nullable(T.array(T.string({ max = 256 }), { max = 64 })),
  Path                     = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
  EnableMediaSourceDisplay = T.nullable(T.boolean()),
  OfficialRating           = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
  CustomRating             = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
  ChannelId                = T.nullable(jf_id()),
  ChannelName              = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
  Overview                 = T.nullable(T.string({ max = 65536, not_match = "[\\x00-\\x1f]" })),
  Taglines                 = T.nullable(T.array(T.string({ max = 1024 }), { max = 32 })),
  Genres                   = T.nullable(T.array(T.string({ max = 256 }), { max = 128 })),
  CommunityRating          = T.nullable(T.number()),
  CumulativeRunTimeTicks   = T.nullable(T.number({ integer = true, min = 0 })),
  RunTimeTicks             = T.nullable(T.number({ integer = true, min = 0 })),
  PlayAccess               = T.nullable(T.string({ max = 8, enum = { Full=true, ["None"]=true } })),
  AspectRatio              = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
  ProductionYear           = T.nullable(T.number({ integer = true })),
  IsPlaceHolder            = T.nullable(T.boolean()),
  Number                   = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  ChannelNumber            = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  IndexNumber              = T.nullable(T.number({ integer = true })),
  IndexNumberEnd           = T.nullable(T.number({ integer = true })),
  ParentIndexNumber        = T.nullable(T.number({ integer = true })),
  RemoteTrailers           = T.nullable(T.array(jf_media_url, { max = 32 })),
  ProviderIds              = T.nullable(T.dict(T.string({ max = 512, not_match = "[\\x00-\\x1f]" }))),
  IsHD                     = T.nullable(T.boolean()),
  IsFolder                 = T.nullable(T.boolean()),
  ParentId                 = T.nullable(jf_id()),
  Type                     = T.nullable(T.string({ max = 32, enum = BASE_ITEM_KIND_ENUM })),
  People                   = T.nullable(T.array(jf_base_item_person, { max = 512 })),
  Studios                  = T.nullable(T.array(jf_name_guid_pair, { max = 64 })),
  GenreItems               = T.nullable(T.array(jf_name_guid_pair, { max = 128 })),
  ParentLogoItemId         = T.nullable(jf_id()),
  ParentBackdropItemId     = T.nullable(jf_id()),
  ParentBackdropImageTags  = T.nullable(T.array(T.string({ max = 256 }), { max = 32 })),
  LocalTrailerCount        = T.nullable(T.number({ integer = true, min = 0 })),
  -- .UserData: UserItemDataDto - small, reuse the shape already defined for
  -- "useritems userdata set" elsewhere in this file if present; otherwise
  -- accept generically (a metadata-editor save round-trips this read-only).
  UserData                 = T.any(),
  RecursiveItemCount       = T.nullable(T.number({ integer = true, min = 0 })),
  ChildCount               = T.nullable(T.number({ integer = true, min = 0 })),
  SeriesName               = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  SeriesId                 = T.nullable(jf_id()),
  SeasonId                 = T.nullable(jf_id()),
  SpecialFeatureCount      = T.nullable(T.number({ integer = true, min = 0 })),
  DisplayPreferencesId     = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  Status                   = T.nullable(T.string({ max = 16,
    enum = { Continuing=true, Ended=true, Unreleased=true } })),
  AirTime                  = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  AirDays                  = T.nullable(T.array(T.string({ max = 16, enum = DAY_OF_WEEK_ENUM }), { max = 7 })),
  Tags                     = T.nullable(T.array(T.string({ max = 256 }), { max = 256 })),
  PrimaryImageAspectRatio  = T.nullable(T.number()),
  Artists                  = T.nullable(T.array(T.string({ max = 1024 }), { max = 128 })),
  ArtistItems              = T.nullable(T.array(jf_name_guid_pair, { max = 128 })),
  Album                    = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  CollectionType           = T.nullable(T.string({ max = 16, enum = {
    movies=true, tvshows=true, music=true, musicvideos=true,
    homevideos=true, boxsets=true, books=true, mixed=true } })),
  DisplayOrder             = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  AlbumId                  = T.nullable(jf_id()),
  AlbumPrimaryImageTag     = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  SeriesPrimaryImageTag    = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  AlbumArtist              = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  AlbumArtists             = T.nullable(T.array(jf_name_guid_pair, { max = 64 })),
  SeasonName               = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  -- MediaStream[] - transcoding-engine-specific (codec/profile/level/color
  -- metadata/...), same T.any() posture as MediaSources above.
  MediaStreams             = T.any(),
  VideoType                = T.nullable(T.string({ max = 16,
    enum = { VideoFile=true, Iso=true, Dvd=true, BluRay=true } })),
  PartCount                = T.nullable(T.number({ integer = true, min = 0 })),
  MediaSourceCount         = T.nullable(T.number({ integer = true, min = 0 })),
  ImageTags                = T.nullable(T.dict(T.string({ max = 256, not_match = "[\\x00-\\x1f]" }))),
  BackdropImageTags        = T.nullable(T.array(T.string({ max = 256 }), { max = 32 })),
  ScreenshotImageTags      = T.nullable(T.array(T.string({ max = 256 }), { max = 32 })),
  ParentLogoImageTag       = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  ParentArtItemId          = T.nullable(jf_id()),
  ParentArtImageTag        = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  SeriesThumbImageTag      = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  ImageBlurHashes          = T.nullable(T.dict(T.dict(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })))),
  SeriesStudio             = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
  ParentThumbItemId        = T.nullable(jf_id()),
  ParentThumbImageTag      = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  ParentPrimaryImageItemId = T.nullable(jf_id()),
  ParentPrimaryImageTag    = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  Chapters                 = T.nullable(T.array(jf_chapter_info, { max = 4096 })),
  Trickplay                = T.nullable(T.dict(T.dict(jf_trickplay_info_dto))),
  LocationType             = T.nullable(T.string({ max = 16,
    enum = { FileSystem=true, Remote=true, Virtual=true, Offline=true } })),
  IsoType                  = T.nullable(T.string({ max = 16, not_match = "[\\x00-\\x1f]" })),
  MediaType                = T.nullable(T.string({ max = 16,
    enum = { Unknown=true, Video=true, Audio=true, Photo=true, Book=true } })),
  EndDate                  = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  LockedFields              = T.nullable(T.array(T.string({ max = 24, enum = {
    Cast=true, Genres=true, ProductionLocations=true, Studios=true, Tags=true,
    Name=true, Overview=true, Runtime=true, OfficialRating=true } }), { max = 16 })),
  TrailerCount             = T.nullable(T.number({ integer = true, min = 0 })),
  MovieCount               = T.nullable(T.number({ integer = true, min = 0 })),
  SeriesCount              = T.nullable(T.number({ integer = true, min = 0 })),
  ProgramCount             = T.nullable(T.number({ integer = true, min = 0 })),
  EpisodeCount             = T.nullable(T.number({ integer = true, min = 0 })),
  SongCount                = T.nullable(T.number({ integer = true, min = 0 })),
  AlbumCount               = T.nullable(T.number({ integer = true, min = 0 })),
  ArtistCount              = T.nullable(T.number({ integer = true, min = 0 })),
  MusicVideoCount          = T.nullable(T.number({ integer = true, min = 0 })),
  LockData                 = T.nullable(T.boolean()),
  Width                    = T.nullable(T.number({ integer = true, min = 0 })),
  Height                   = T.nullable(T.number({ integer = true, min = 0 })),
  CameraMake               = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  CameraModel              = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  Software                 = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  ExposureTime             = T.nullable(T.number()),
  FocalLength              = T.nullable(T.number()),
  ImageOrientation         = T.nullable(T.string({ max = 16,
    enum = { TopLeft=true, TopRight=true, BottomRight=true, BottomLeft=true,
             LeftTop=true, RightTop=true, RightBottom=true, LeftBottom=true } })),
  Aperture                 = T.nullable(T.number()),
  ShutterSpeed             = T.nullable(T.number()),
  Latitude                 = T.nullable(T.number()),
  Longitude                = T.nullable(T.number()),
  Altitude                 = T.nullable(T.number()),
  IsoSpeedRating           = T.nullable(T.number({ integer = true })),
  SeriesTimerId            = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  ProgramId                = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  ChannelPrimaryImageTag   = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  StartDate                = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
  CompletionPercentage     = T.nullable(T.number({ min = 0, max = 100 })),
  IsRepeat                 = T.nullable(T.boolean()),
  EpisodeTitle             = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
  ChannelType              = T.nullable(T.string({ max = 8, enum = { TV=true, Radio=true } })),
  Audio                    = T.nullable(T.string({ max = 16,
    enum = { Mono=true, Stereo=true, Dolby=true, DolbyDigital=true, Thx=true, Atmos=true } })),
  IsMovie                  = T.nullable(T.boolean()),
  IsSports                 = T.nullable(T.boolean()),
  IsSeries                 = T.nullable(T.boolean()),
  IsLive                   = T.nullable(T.boolean()),
  IsNews                   = T.nullable(T.boolean()),
  IsKids                   = T.nullable(T.boolean()),
  IsPremiere               = T.nullable(T.boolean()),
  TimerId                  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
  NormalizationGain        = T.nullable(T.number()),
  -- Self-referential (CurrentProgram: BaseItemDto) - T.any(), not recursed.
  CurrentProgram           = T.any(),
})

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
      -- Plugin-provided HTML config page. DashboardController.cs's real
      -- route is "web/ConfigurationPage" (capital P) - confirmed live via
      -- utils/dashboard.js:120's actual ApiClient.getUrl() call (the real
      -- wire request), not the internal SPA route id used elsewhere in the
      -- same file (utils/dashboard.js:116's lowercase 'configurationpage'
      -- string, a client-side routing key, never sent over the wire). The
      -- previous `(?:C|c)onfigurationpage` pattern here only matched
      -- "Configurationpage"/"configurationpage" - never the real
      -- "ConfigurationPage" the web client actually sends, a real false-
      -- positive risk for the admin dashboard's plugin-config pages.
      name    = "web configurationpage",
      method  = "GET",
      paths   = { [[^/web/(?:ConfigurationPage|configurationpage)$]] },
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
    { name="branding css",          method="GET",        path=[[^/Branding/Css(?:\.css)?$]], no_body=true },
    -- branding splashscreen: see ImageController's "Images" section below
    -- (ImageController.cs owns GET/POST/DELETE .../Splashscreen, not
    -- BrandingController - this used to be a stub duplicate here with no
    -- schema at all, shadowing the real one and making it unreachable).

    -------------------------------------------------------------------------
    -- System
    -------------------------------------------------------------------------
    -- GET/POST split into separate entries (first-match-wins) so the json
    -- schema below only applies to the POST body, not the bodyless GET.
    { name="system config",          method="GET",  path=[[^/System/Configuration$]], no_body=true },
    { name="system config update",   method="POST", path=[[^/System/Configuration$]],
      content_types = { "application/json" }, json = jf_server_configuration },
    -- ConfigurationController.cs: GetNamedConfiguration/UpdateNamedConfiguration
    -- are [HttpGet/Post("Configuration/{key}")] - a truly generic key (any
    -- core or plugin-registered configuration section, not a fixed set).
    -- Replaces the previous livetv/branding/network/xbmcmetadata/encoding/
    -- metadata-only routes (a real gap: any OTHER section, e.g. a plugin's
    -- own, or the dedicated "Configuration/Branding" POST route - whose key
    -- is capitalized, case-sensitive-different from the old lowercase-only
    -- "branding" entry - would have been blocked).
    { name="system config named",    method="GET",  path=[[^/System/Configuration/[A-Za-z][A-Za-z0-9]{0,63}$]], no_body=true },
    -- UpdateNamedConfiguration binds [FromBody, Required] System.Text.Json.JsonDocument,
    -- then deserializes it against whatever type _configurationManager.GetConfigurationType(key)
    -- returns for that specific key - a genuinely key-dependent, dynamically-typed
    -- body (core config sections like "branding"/"encoding"/"network", or any
    -- plugin-registered section). Cannot be meaningfully schema-typed without
    -- enumerating every installed plugin's config class; content-type + size
    -- limit is the practical ceiling here (same posture as mediawiki's
    -- dynamic_type_expr fields and this file's jf_provider_list()).
    { name="system config named update", method="POST", path=[[^/System/Configuration/[A-Za-z][A-Za-z0-9]{0,63}$]],
      content_types = { "application/json" } },
    { name="system config metadata options default", method="GET", path=[[^/System/Configuration/MetadataOptions/Default$]], no_body=true },
    -- [Obsolete], real handler is a security-hardened no-op server-side.
    { name="system mediaencoder path", method="POST", path=[[^/System/MediaEncoder/Path$]],
      content_type = "application/json",
      json = T.object({
        Path     = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
        PathType = T.nullable(T.string({ max = 16, not_match = "[\\x00-\\x1f]" })),
      }) },
    { name="system logs",            method="GET",           path=[[^/System/Logs$]],                       no_body=true },
    { name="system logs file",       method="GET",           path=[[^/System/Logs/Log$]],                   no_body=true,
      query = T.object({ name = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }) }, { required = { name = true } }) },
    { name="system restart",         method="POST",          path=[[^/System/Restart$]],                    no_body=true },
    { name="system shutdown",        method="POST",          path=[[^/System/Shutdown$]],                   no_body=true },
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
    -- EnvironmentController.ValidatePath(ValidatePathDto): Path is nullable
    -- string, ValidateWritable defaults false (non-nullable bool - JSON
    -- omission still binds false), IsFile is a nullable bool (tri-state:
    -- unset = "check either file or dir exists").
    { name="env validatepath",  method="POST", path=[[^/Environment/ValidatePath$]],
      content_type = "application/json",
      json = T.object({
        Path             = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
        ValidateWritable = T.nullable(T.boolean()),
        IsFile           = T.nullable(T.boolean()),
      }) },
    -- [Obsolete], always returns an empty array server-side - routed anyway
    -- so an old client gets a clean empty response instead of a WAF block.
    { name="env networkshares", method="GET",  path=[[^/Environment/NetworkShares$]], no_body=true },

    -------------------------------------------------------------------------
    -- Libraries
    -------------------------------------------------------------------------
    { name="lib options",  method="GET",        path=[[^/Libraries/AvailableOptions$]], no_body=true },
    { name="lib folders",  method="GET",        path=[[^/Library/MediaFolders$]],       no_body=true },

    -- LibraryController.cs - full audit against real source, not just
    -- live-reported false positives.
    { name="lib refresh",  method="POST",       path=[[^/Library/Refresh$]],            no_body=true },
    { name="lib physicalpaths", method="GET",   path=[[^/Library/PhysicalPaths$]],      no_body=true },
    -- PostAddedSeries/PostUpdatedSeries share one handler across both
    -- [HttpPost] routes (external metadata-source webhooks - Added is the
    -- original name, Updated the newer alias, both still live).
    { name="lib series updated", method="POST", path=[[^/Library/Series/(?:Added|Updated)$]], no_body=true,
      query = T.object({ tvdbId = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })) }) },
    { name="lib movies updated", method="POST", path=[[^/Library/Movies/(?:Added|Updated)$]], no_body=true,
      query = T.object({
        tmdbId = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
        imdbId = T.nullable(T.string({ max = 64, not_match = "[\\x00-\\x1f]" })),
      }) },
    { name="lib media updated", method="POST",  path=[[^/Library/Media/Updated$]],
      content_type = "application/json",
      json = T.object({
        Updates = T.nullable(T.array(T.object({
          Path       = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
          UpdateType = T.nullable(T.string({ max = 16, enum = { Created=true, Modified=true, Deleted=true } })),
        }), { max = 10000 })),
      }) },

    -- LibraryStructureController.cs - the whole controller was only
    -- shallowly covered (bare GET/POST /VirtualFolders, no schema at all,
    -- and every /VirtualFolders/* sub-route missing outright). Confirmed
    -- live: real dashboard "manage libraries" actions (remove a library,
    -- remove/add/update a media path, rename a library, edit library
    -- options) were ALL being blocked as "no route matched" - this is the
    -- controller behind Dashboard > Libraries in its entirety, not an edge
    -- case. Split into one route per (method, sub-path) since each needs
    -- its own distinct query/body schema; GET has none.
    { name="lib virtual list", method="GET", path=[[^/Library/VirtualFolders$]], no_body=true },
    { name="lib virtual add",  method="POST", path=[[^/Library/VirtualFolders$]],
      content_type = "application/json",
      query = T.object({
        name           = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
        collectionType = T.nullable(T.string({ max = 16, enum = {
          movies=true, tvshows=true, music=true, musicvideos=true,
          homevideos=true, boxsets=true, books=true, mixed=true } })),
        -- [ModelBinder(CommaDelimitedCollectionModelBinder)]: one query
        -- value, comma-joined, not repeated ?paths=a&paths=b.
        paths          = T.nullable(T.string({ max = 8192, not_match = "[\\x00-\\x1f]" })),
        refreshLibrary = T.nullable(T.bool_query()),
      }, { required = { name = true } }),
      json = T.nullable(T.object({ LibraryOptions = T.nullable(jf_library_options) })) },
    { name="lib virtual remove", method="DELETE", path=[[^/Library/VirtualFolders$]], no_body=true,
      query = T.object({
        name           = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
        refreshLibrary = T.nullable(T.bool_query()),
      }, { required = { name = true } }) },
    { name="lib virtual rename", method="POST", path=[[^/Library/VirtualFolders/Name$]], no_body=true,
      query = T.object({
        name           = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
        newName        = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
        refreshLibrary = T.nullable(T.bool_query()),
      }, { required = { name = true, newName = true } }) },
    { name="lib virtual paths add", method="POST", path=[[^/Library/VirtualFolders/Paths$]],
      content_type = "application/json",
      query = T.object({ refreshLibrary = T.nullable(T.bool_query()) }),
      json = T.object({
        Name     = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
        Path     = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
        PathInfo = T.nullable(jf_media_path_info),
      }, { required = { Name = true } }) },
    { name="lib virtual paths update", method="POST", path=[[^/Library/VirtualFolders/Paths/Update$]],
      content_type = "application/json",
      json = T.object({
        Name     = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
        PathInfo = jf_media_path_info,
      }, { required = { Name = true, PathInfo = true } }) },
    -- LibraryStructureController.cs: [HttpDelete("Paths")] RemoveMediaPath -
    -- all three params are [FromQuery], no body. Confirmed live: this exact
    -- shape (DELETE .../Paths?refreshLibrary=false&path=...&name=...) was a
    -- real false positive - the dashboard's "remove folder from library"
    -- action, blocked outright since no route matched /Paths at all.
    { name="lib virtual paths remove", method="DELETE", path=[[^/Library/VirtualFolders/Paths$]],
      no_body = true,
      query   = T.object({
        name          = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
        path          = T.string({ max = 4096, not_match = "[\\x00-\\x1f]" }),
        refreshLibrary = T.nullable(T.bool_query()),
      }, { required = { name = true, path = true } }) },
    -- Confirmed live (second false positive from the same "manage
    -- libraries" flow): editing a library's advanced options 403'd the
    -- same way - no route existed for LibraryOptions at all.
    { name="lib virtual library options", method="POST", path=[[^/Library/VirtualFolders/LibraryOptions$]],
      content_type = "application/json",
      json = T.object({
        Id             = T.nullable(jf_id()),
        LibraryOptions = T.nullable(jf_library_options),
      }) },

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
    { name="repositories",      method="GET",  path=[[^/Repositories$]], no_body=true },
    { name="repositories set",  method="POST", path=[[^/Repositories$]],
      content_types = { "application/json" }, json = T.array(jf_repository_info, { max = 64 }) },
    { name="packages",          method="GET",           path=[[^/Packages$]],   no_body=true },
    -- PackageController.cs: GetPackageInfo's `name` is looked up against the
    -- live plugin-repository catalog (IInstallationManager.GetAvailablePackages),
    -- not a fixed set - confirmed live via source; the previous hardcoded
    -- 6-name enum here (AudioDB|MusicBrainz|...) was a real gap (any other
    -- catalog plugin, e.g. a newly-added repository's, would 403). Same
    -- name-segment convention as Artists/Genres/etc. elsewhere in this file.
    { name="packages named",    method="GET",           path=[[^/Packages/[^/\x00-\x1f]{1,200}$]], no_body=true,
      query = T.object({ assemblyGuid = T.nullable(jf_id()) }) },
    -- InstallPackage: same "any catalog name" reasoning - was hardcoded to
    -- one literal name ("Home Screen Sections") when real installs cover
    -- any package.
    { name="packages installed",method="POST", path=[[^/Packages/Installed/[^/\x00-\x1f]{1,200}$]], no_body=true,
      query = T.object({
        assemblyGuid  = T.nullable(jf_id()),
        version       = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
        repositoryUrl = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
      }) },
    { name="packages installing cancel", method="DELETE", path="^/Packages/Installing/" .. ID .. "$", no_body=true },
    { name="plugins",           method="GET", path=[[^/Plugins$]],                                          no_body=true },
    -- PluginsController.cs: bare {pluginId}/{version} is [HttpDelete] only
    -- (GET only exists at .../Image, already a separate route below).
    { name="plugins version",   method="DELETE", path=[[^/Plugins/]] .. HEX32 .. [[/[0-9.]+$]],               no_body=true },
    { name="plugins image",     method="GET", path=[[^/Plugins/]] .. HEX32 .. [[/[0-9.]+/Image$]],         no_body=true },
    -- Full audit against real source, not just live-reported false
    -- positives: Enable/Disable/bare-uninstall/Configuration/Manifest were
    -- all missing entirely.
    { name="plugins enable",    method="POST", path=[[^/Plugins/]] .. HEX32 .. [[/[0-9.]+/Enable$]],  no_body=true },
    { name="plugins disable",   method="POST", path=[[^/Plugins/]] .. HEX32 .. [[/[0-9.]+/Disable$]], no_body=true },
    -- [Obsolete] uninstall-without-version form, kept for old clients.
    { name="plugins uninstall", method="DELETE", path=[[^/Plugins/]] .. HEX32 .. [[$]], no_body=true },
    { name="plugins config get", method="GET",  path=[[^/Plugins/]] .. HEX32 .. [[/Configuration$]], no_body=true },
    -- Plugin-defined configuration shape (BasePluginConfiguration subclass,
    -- different per plugin) - content-type-only, same big/unknown-DTO
    -- convention as elsewhere in this file.
    { name="plugins config set", method="POST", path=[[^/Plugins/]] .. HEX32 .. [[/Configuration$]],
      content_types = { "application/json" } },
    { name="plugins manifest",  method="POST", path=[[^/Plugins/]] .. HEX32 .. [[/Manifest$]], no_body=true },
    { name="backup",            method="GET", path=[[^/Backup$]],                                           no_body=true },
    { name="backup create",     method="POST", path=[[^/Backup/Create$]],
      content_type = "application/json",
      json = T.nullable(T.object({
        Metadata  = T.nullable(T.boolean()),
        Trickplay = T.nullable(T.boolean()),
        Subtitles = T.nullable(T.boolean()),
        Database  = T.nullable(T.boolean()),
      })) },
    { name="backup restore",    method="POST", path=[[^/Backup/Restore$]],
      content_type = "application/json",
      json = T.object({
        ArchiveFileName = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
      }, { required = { ArchiveFileName = true } }) },
    { name="backup manifest",   method="GET", path=[[^/Backup/Manifest$]], no_body=true,
      query = T.object({ path = T.string({ max = 4096, not_match = "[\\x00-\\x1f]" }) },
                        { required = { path = true } }) },

    -------------------------------------------------------------------------
    -- Users
    -------------------------------------------------------------------------
    -- GET/POST split (first-match-wins): GetUsers (query filters, no body) vs
    -- UpdateUser (?userId= query + UserDto body) bind completely different shapes.
    { name="users list",        method="GET", paths={ [[^/Users$]], [[^/users$]] }, no_body=true,
      query = T.object({
        isHidden   = T.nullable(T.bool_query()),
        isDisabled = T.nullable(T.bool_query()),
      }) },
    { name="users list update", method="POST", paths={ [[^/Users$]], [[^/users$]] },
      content_types = { "application/json" },
      query = T.object({ userId = T.nullable(jf_id()) }),
      json  = jf_user_dto },
    { name="users public",      method="GET",  paths={ [[^/Users/Public$]], [[^/users/public$]] }, no_body=true },
    { name="users me",          method="GET",  path=[[^/Users/Me$]],             no_body=true },
    { name="users new",         method="POST", path=[[^/Users/New$]],
      content_types = { "application/json" },
      json = T.object({
        Name     = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }),
        Password = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
      }, { required = { Name = true } }) },
    -- AuthenticateUserByName request: both fields are C#-nullable, but a
    -- real login always sends both (confirmed live via test/jellyfin_login.lua)
    -- - required here per the "prefer strict" default.
    { name="users auth",        method="POST", paths={
        [[^/Users/AuthenticateByName$]],
        [[^/Users/authenticatebyname$]],
      },
      content_types = { "application/json" },
      json = T.object({
        Username = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }),
        Pw       = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
      }, { required = { Username = true, Pw = true } }) },
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
      name          = "users password",
      method        = "POST",
      path          = [[^/Users/Password$]],
      content_types = { "application/json" },
      query         = T.object({ userId = T.nullable(jf_id()) }),
      json          = jf_update_user_password(),
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
      -- GET (GetUserById) and DELETE (DeleteUser) carry no body; POST
      -- (UpdateUserLegacy) binds the same UserDto as "users list update"
      -- above. Split into separate entries (first-match-wins) so the json
      -- schema only applies to the POST leg.
      name    = "users by id",
      methods = { "GET", "DELETE" },
      path    = "^/Users/" .. ID .. "$",
      no_body = true,
    },
    { name="users by id update", method="POST", path="^/Users/" .. ID .. "$",
      content_types = { "application/json" }, json = jf_user_dto },
    -- UserController.cs: UpdateUserConfigurationLegacy is [HttpPost("{userId}/Configuration")]
    -- only - no GET.
    { name="users configuration", method="POST", path="^/Users/" .. ID .. "/Configuration$",
      content_types = { "application/json" }, json = jf_user_configuration },
    -- Current-form UpdateUserConfiguration (?userId= query instead of a path
    -- segment) - previously a real, flagged gap; addressed now as part of
    -- the full controller audit.
    { name="users configuration current", method="POST", path=[[^/Users/Configuration$]],
      content_type = "application/json",
      query = T.object({ userId = T.nullable(jf_id()) }),
      json  = jf_user_configuration },
    -- [Obsolete] legacy userId-in-path authenticate/password/easypassword
    -- forms - AuthenticateUser/UpdateUserPasswordLegacy/UpdateUserEasyPassword
    -- all just delegate to (or, for EasyPassword, unconditionally Forbid()
    -- the same shape as) their current-form siblings above.
    { name="users authenticate legacy", method="POST", path="^/Users/" .. ID .. "/Authenticate$", no_body=true,
      query = T.object({ pw = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }) }, { required = { pw = true } }) },
    -- UpdateUserPassword: all 4 fields C#-nullable (ResetPassword defaults
    -- false), same shape as "users password" above.
    { name="users password legacy", method="POST", path="^/Users/" .. ID .. "/Password$",
      content_types = { "application/json" },
      json = jf_update_user_password() },
    { name="users easypassword legacy", method="POST", path="^/Users/" .. ID .. "/EasyPassword$",
      content_type = "application/json" },
    { name="users policy",        method="POST",           path="^/Users/" .. ID .. "/Policy$",
      content_types = { "application/json" }, json = jf_user_policy },
    { name="users grouping",      method="GET",            path="^/Users/" .. ID .. "/GroupingOptions$", no_body=true },
    {
      name    = "userviews grouping",
      method  = "GET",
      path    = [[^/UserViews/GroupingOptions$]],
      no_body = true,
      query   = T.object({ userId = T.nullable(jf_id()) }),
    },
    -- [Obsolete] legacy alias for GetItems - identical param set to "items"
    -- above minus userId (it's the {userId} path segment here instead).
    { name="users items",         method="GET",            path="^/Users/" .. ID .. "/Items$",           no_body=true,
      query = T.object(jf_get_items_query(false)) },
    { name="users items latest",  method="GET",            path="^/Users/" .. ID .. "/Items/Latest$",    no_body=true },
    { name="users items resume",  method="GET",            path="^/Users/" .. ID .. "/Items/Resume$",    no_body=true },
    { name="users items by id",   method="GET",            path="^/Users/" .. ID .. "/Items/" .. ID .. "$", no_body=true },
    { name="users items intros",  method="GET",            path="^/Users/" .. ID .. "/Items/" .. ID .. "/Intros$", no_body=true },
    { name="items intros",        method="GET",            path="^/Items/" .. ID .. "/Intros$", no_body=true },
    -- UserLibraryController.cs - full audit against real source, not just
    -- live-reported false positives.
    { name="items root",         method="GET", path=[[^/Items/Root$]], no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    { name="users items root",   method="GET", path="^/Users/" .. ID .. "/Items/Root$", no_body=true },
    { name="items localtrailers", method="GET", path="^/Items/" .. ID .. "/LocalTrailers$", no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    { name="users items localtrailers", method="GET", path="^/Users/" .. ID .. "/Items/" .. ID .. "/LocalTrailers$", no_body=true },
    { name="useritems rating set", method="POST", path="^/UserItems/" .. ID .. "/Rating$", no_body=true,
      query = T.object({
        userId = T.nullable(jf_id()),
        likes  = T.nullable(T.bool_query()),
      }) },
    { name="useritems rating delete", method="DELETE", path="^/UserItems/" .. ID .. "/Rating$", no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    { name="users items rating set", method="POST", path="^/Users/" .. ID .. "/Items/" .. ID .. "/Rating$", no_body=true,
      query = T.object({ likes = T.nullable(T.bool_query()) }) },
    { name="users items rating delete", method="DELETE", path="^/Users/" .. ID .. "/Items/" .. ID .. "/Rating$", no_body=true },
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
    -- ItemsController.cs GetItemUserData/UpdateItemUserData - full audit
    -- against real source, not just live-reported false positives.
    { name="useritems userdata get", method="GET", path="^/UserItems/" .. ID .. "/UserData$", no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    { name="users items userdata get", method="GET", path="^/Users/" .. ID .. "/Items/" .. ID .. "/UserData$", no_body=true },
    { name="useritems userdata set", method="POST", path="^/UserItems/" .. ID .. "/UserData$",
      content_type = "application/json",
      query = T.object({ userId = T.nullable(jf_id()) }),
      json = T.object({
        Rating                = T.nullable(T.number({ min = 0, max = 10 })),
        PlayedPercentage       = T.nullable(T.number({ min = 0, max = 100 })),
        UnplayedItemCount      = T.nullable(T.number({ integer = true, min = 0 })),
        PlaybackPositionTicks  = T.nullable(T.number({ integer = true, min = 0, max = 1e13 })),
        PlayCount              = T.nullable(T.number({ integer = true, min = 0 })),
        IsFavorite              = T.nullable(T.boolean()),
        Likes                   = T.nullable(T.boolean()),
        LastPlayedDate          = T.nullable(T.iso8601()),
        Played                  = T.nullable(T.boolean()),
        Key                     = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
        ItemId                  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
      }) },
    { name="users items userdata set", method="POST", path="^/Users/" .. ID .. "/Items/" .. ID .. "/UserData$",
      content_type = "application/json",
      json = T.object({
        Rating                = T.nullable(T.number({ min = 0, max = 10 })),
        PlayedPercentage       = T.nullable(T.number({ min = 0, max = 100 })),
        UnplayedItemCount      = T.nullable(T.number({ integer = true, min = 0 })),
        PlaybackPositionTicks  = T.nullable(T.number({ integer = true, min = 0, max = 1e13 })),
        PlayCount              = T.nullable(T.number({ integer = true, min = 0 })),
        IsFavorite              = T.nullable(T.boolean()),
        Likes                   = T.nullable(T.boolean()),
        LastPlayedDate          = T.nullable(T.iso8601()),
        Played                  = T.nullable(T.boolean()),
        Key                     = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
        ItemId                  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
      }) },
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
    -- MarkFavoriteItemLegacy/UnmarkFavoriteItemLegacy: userId+itemId both
    -- path segments, no other params - unlike "userfavoriteitems" below.
    { name="favorite items", methods={"POST","DELETE"}, path="^/Users/" .. ID .. "/FavoriteItems/[0-9A-Za-z_.-]+$", no_body=true },
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
    -- /UserImage: see ImageController's "Images" section below (used to be
    -- a schema-less stub here, shadowing and making unreachable the real
    -- GET/POST/DELETE routes with their actual query/content-type checks).
    { name="useritems resume", method="GET", path=[[^/UserItems/Resume$]], no_body=true },
    { name="userviews",    method="GET", path=[[^/UserViews$]],          no_body=true },

    -------------------------------------------------------------------------
    -- Items
    -------------------------------------------------------------------------
    -- ItemsController.GetItems - no POST /Items exists anywhere on the real
    -- server (confirmed: grepped every controller for HttpPost("Items") with
    -- no id segment - only HttpPost("Items/{itemId}"), a different route,
    -- below). The previous methods={"GET","POST"} here was a real gap in the
    -- other direction: it accepted a POST the real server 404s on, with zero
    -- schema on either leg.
    { name="items", method="GET", path=[[^/Items$]], no_body=true,
      query = T.object(jf_get_items_query(true)) },
    -- UserLibraryController.GetItem (GET, ?userId=) / LibraryController.
    -- DeleteItem (DELETE, no params) carry no body; ItemUpdateController.
    -- UpdateItem (POST) binds the full BaseItemDto, now fully typed via
    -- jf_base_item_dto() (see its definition above for what's exempted
    -- and why).
    { name="items by id", methods={"GET","DELETE"}, path="^/Items/" .. ID .. "$", no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    { name="items by id update", method="POST", path="^/Items/" .. ID .. "$",
      content_types={"application/json"}, json = jf_base_item_dto },
    -- LibraryController.DeleteItems: bulk delete, comma-delimited ?ids=.
    { name="items delete bulk",  method="DELETE",        path=[[^/Items$]], no_body=true,
      query = T.object({ ids = T.nullable(T.string({ max = 65536, not_match = "[\\x00-\\x1f]" })) }) },
    { name="items counts",       method="GET",           path=[[^/Items/Counts$]],         no_body=true },
    { name="items latest",       method="GET",           path=[[^/Items/Latest$]],         no_body=true },
    { name="items similar",      method="GET",           path="^/Items/" .. ID .. "/Similar$",             no_body=true },
    -- GetSimilarItems: one handler, six [HttpGet] route attributes
    -- (Artists/Albums/Shows/Movies/Trailers/Items) - only the /Items/ form
    -- above was covered; the other five were a real gap.
    { name="similar by kind",    method="GET",
      path = "^/(?:Artists|Albums|Shows|Movies|Trailers)/" .. ID .. "/Similar$", no_body=true,
      query = T.object({
        excludeArtistIds = T.nullable(T.string({ max = 8192, not_match = "[\\x00-\\x1f]" })),
        userId           = T.nullable(jf_id()),
        limit             = T.nullable(T.number_query({ integer = true, min = 0, max = 10000 })),
        fields            = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
      }) },
    -- ItemRefreshController.RefreshItem: query params only, no body.
    { name="items refresh",      method="POST",          path="^/Items/" .. ID .. "/Refresh$", no_body=true,
      query = T.object({
        metadataRefreshMode = T.nullable(T.string({ max = 16,
          enum = { None=true, ValidationOnly=true, Default=true, FullRefresh=true } })),
        imageRefreshMode    = T.nullable(T.string({ max = 16,
          enum = { None=true, ValidationOnly=true, Default=true, FullRefresh=true } })),
        replaceAllMetadata  = T.nullable(T.bool_query()),
        replaceAllImages    = T.nullable(T.bool_query()),
        regenerateTrickplay = T.nullable(T.bool_query()),
      }) },
    { name="items metadata editor", method="GET",        path="^/Items/" .. ID .. "/MetadataEditor$",      no_body=true },
    { name="items contenttype",  method="POST",          path="^/Items/" .. ID .. "/ContentType$",         no_body=true,
      query = T.object({ contentType = T.nullable(T.string({ max = 128, not_match = "[\\x00-\\x1f]" })) }) },
    { name="items download",     method="GET",           path="^/Items/" .. ID .. "/Download$",            no_body=true },
    { name="items file",         method="GET",           path="^/Items/" .. ID .. "/File$",                no_body=true },
    -- [Obsolete], real handler always `return new QueryResult<>()` (dead
    -- server-side, kept only so old clients don't 404).
    { name="items criticreviews", method="GET",          path="^/Items/" .. ID .. "/CriticReviews$",       no_body=true },
    { name="items ancestors",    method="GET",           path="^/Items/" .. ID .. "/Ancestors$",           no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    -- ThemeSongs/ThemeVideos share GetThemeSongs/GetThemeVideos's own query
    -- shape (already used by "items thememedia" below, which calls both
    -- internally with the same params).
    { name="items themesongs",   method="GET",           path="^/Items/" .. ID .. "/ThemeSongs$",          no_body=true,
      query = T.object({
        userId            = T.nullable(jf_id()),
        inheritFromParent = T.nullable(T.bool_query()),
        sortBy            = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
        sortOrder         = T.nullable(T.string({ max = 32, enum = { Ascending=true, Descending=true } })),
      }) },
    { name="items themevideos",  method="GET",           path="^/Items/" .. ID .. "/ThemeVideos$",         no_body=true,
      query = T.object({
        userId            = T.nullable(jf_id()),
        inheritFromParent = T.nullable(T.bool_query()),
        sortBy            = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
        sortOrder         = T.nullable(T.string({ max = 32, enum = { Ascending=true, Descending=true } })),
      }) },
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
    -- Full audit against real source (InstantMixController.cs), not just
    -- live-reported false positives - only the Items/ form above was
    -- covered; the other five path-segment forms plus the two ?id=
    -- (Obsolete but still live) forms were a real gap.
    { name="songs instantmix",    method="GET", path="^/Songs/" .. ID .. "/InstantMix$",    no_body=true, query=T.object(jf_instantmix_query()) },
    { name="albums instantmix",   method="GET", path="^/Albums/" .. ID .. "/InstantMix$",   no_body=true, query=T.object(jf_instantmix_query()) },
    { name="playlists instantmix",method="GET", path="^/Playlists/" .. ID .. "/InstantMix$",no_body=true, query=T.object(jf_instantmix_query()) },
    { name="artists instantmix by id", method="GET", path="^/Artists/" .. ID .. "/InstantMix$", no_body=true, query=T.object(jf_instantmix_query()) },
    { name="musicgenres instantmix by name", method="GET",
      path = "^/MusicGenres/[^/\\x00-\\x1f]{1,200}/InstantMix$", no_body=true, query=T.object(jf_instantmix_query()) },
    { name="artists instantmix",  method="GET", path=[[^/Artists/InstantMix$]], no_body=true,
      -- T.uuid() here, not jf_id() - both routes are [Obsolete] legacy
      -- aliases (GetInstantMixFromArtists2/GetInstantMixFromMusicGenre2)
      -- real clients only reach via a properly-dashed GUID.ToString()
      -- fallback URL. jf_id()'s dashless-hex allowance is for path
      -- segments; a required match-pattern field here also hits a real
      -- test-generator limitation (gen.lua can't synthesize a value for a
      -- generic `match` pattern the way it can for T.uuid()).
      query = T.object((function() local q = jf_instantmix_query(); q.id = T.uuid(); return q end)(),
                        { required = { id = true } }) },
    { name="musicgenres instantmix", method="GET", path=[[^/MusicGenres/InstantMix$]], no_body=true,
      -- T.uuid() here, not jf_id() - both routes are [Obsolete] legacy
      -- aliases (GetInstantMixFromArtists2/GetInstantMixFromMusicGenre2)
      -- real clients only reach via a properly-dashed GUID.ToString()
      -- fallback URL. jf_id()'s dashless-hex allowance is for path
      -- segments; a required match-pattern field here also hits a real
      -- test-generator limitation (gen.lua can't synthesize a value for a
      -- generic `match` pattern the way it can for T.uuid()).
      query = T.object((function() local q = jf_instantmix_query(); q.id = T.uuid(); return q end)(),
                        { required = { id = true } }) },
    -- filterdialog.js / useFetchItems.ts's getQueryFiltersLegacy call -
    -- SuggestionsController.cs - many-optional-filter-field GETs, no_body
    -- and no per-field schema (matches this file's convention for similarly
    -- shaped list endpoints elsewhere, e.g. "livetv recordings").
    { name="items suggestions",       method="GET", path=[[^/Items/Suggestions$]], no_body=true },
    { name="users items suggestions", method="GET", path="^/Users/" .. ID .. "/Suggestions$", no_body=true },
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
    -- FilterController.cs's newer GetQueryFilters - many-optional-filter-
    -- field GET, no per-field schema (matches this file's convention for
    -- similarly shaped list endpoints, e.g. "livetv recordings").
    { name="items filters2", method="GET", path=[[^/Items/Filters2$]], no_body=true },
    { name="items thememedia",   method="GET",           path="^/Items/" .. ID .. "/ThemeMedia$",          no_body=true },
    { name="items remoteimages", method="GET",           path="^/Items/" .. ID .. "/RemoteImages/Providers$", no_body=true },
    { name="items remoteimages list", method="GET",      path="^/Items/" .. ID .. "/RemoteImages$", no_body=true,
      query = T.object({
        type                = T.nullable(T.string({ max = 16, enum = IMAGE_TYPE_ENUM })),
        startIndex          = T.nullable(T.number_query({ integer = true, min = 0 })),
        limit               = T.nullable(T.number_query({ integer = true, min = 0 })),
        providerName        = T.nullable(T.string({ max = 128, not_match = "[\\x00-\\x1f]" })),
        includeAllLanguages = T.nullable(T.bool_query()),
      }) },
    { name="items remoteimages download", method="POST", path="^/Items/" .. ID .. "/RemoteImages/Download$", no_body=true,
      query = T.object({
        type     = T.string({ max = 16, enum = IMAGE_TYPE_ENUM }),
        imageUrl = T.nullable(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" })),
      }, { required = { type = true } }) },
    -- MediaInfoController's GetPlaybackInfo (GET) / GetPostedPlaybackInfo
    -- (POST) - both bind the same [ParameterObsolete] query params (kept for
    -- backwards compatibility, superseded by the POST body). POST body is
    -- jf_playback_info_dto() (see its definition above).
    { name="items playbackinfo", method="GET", path="^/Items/" .. ID .. "/PlaybackInfo$", no_body=true,
      query = jf_playbackinfo_query() },
    { name="items playbackinfo post", method="POST", path="^/Items/" .. ID .. "/PlaybackInfo$",
      content_types = { "application/json" },
      query = jf_playbackinfo_query(),
      json  = jf_playback_info_dto() },
    -- Images (ImageController.cs) - full audit against real source, not
    -- just live-reported false positives: replaces the old Thumb/Logo/
    -- Primary/Backdrop-only routes (a real gap - Art/Disc/Box/Screenshot/
    -- Menu/Chapter/BoxRear/Profile were all unrouted) and adds the by-index,
    -- full-dynamic-resize, admin set/delete/reorder, named-entity
    -- (Artist/Genre/MusicGenre/Person/Studio), user-avatar, and branding-
    -- splashscreen endpoints that had zero coverage at all.
    { name="items images",          method="GET", path="^/Items/" .. ID .. "/Images$",           no_body=true },
    { name="items images by type",  method="GET", path="^/Items/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "$",
      no_body = true, query = jf_image_query() },
    { name="items images by index", method="GET", path="^/Items/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+$",
      no_body = true, query = jf_image_query() },
    -- GetItemImage2: the full dynamic-resize URL form real clients build
    -- directly (no query string at all - every parameter is a path segment).
    { name="items images full", method="GET",
      path = "^/Items/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT ..
             "/[0-9]+/[^/\\x00-\\x1f]{1,256}/" .. -- tag
             "(?:Bmp|Gif|Jpg|Png|Webp|Svg)/" ..   -- format
             "[0-9]+/[0-9]+/[0-9.]+/[0-9]+$",       -- maxWidth/maxHeight/percentPlayed/unplayedCount
      no_body = true },
    { name="items images set",    method="POST", path="^/Items/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "$",
      content_types = IMAGE_CONTENT_TYPES },
    { name="items images set by index", method="POST",
      path = "^/Items/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+$",
      content_types = IMAGE_CONTENT_TYPES },
    { name="items images reorder", method="POST",
      path = "^/Items/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+/Index$", no_body = true,
      query = T.object({ newIndex = T.number_query({ integer = true, min = 0, max = 999 }) },
                        { required = { newIndex = true } }) },
    { name="items images delete", method="DELETE",
      path = "^/Items/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "$", no_body = true },
    { name="items images delete by index", method="DELETE",
      path = "^/Items/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+$", no_body = true },

    -- Named-entity images: Artists/Genres/MusicGenres/Persons/Studios all
    -- bind an identical parameter set to Items' (GetArtistImage/
    -- GetGenreImage/etc. all call the same GetImageInternal as GetItemImage).
    { name="artists images by type", method="GET",
      path = "^/Artists/[^/\\x00-\\x1f]{1,200}/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+$",
      no_body = true, query = jf_image_query() },
    { name="genres images by type", method="GET",
      path = "^/Genres/[^/\\x00-\\x1f]{1,200}/Images/" .. IMAGE_TYPE_ALT .. "$",
      no_body = true, query = jf_image_query() },
    { name="genres images by index", method="GET",
      path = "^/Genres/[^/\\x00-\\x1f]{1,200}/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+$",
      no_body = true, query = jf_image_query() },
    { name="musicgenres images by type", method="GET",
      path = "^/MusicGenres/[^/\\x00-\\x1f]{1,200}/Images/" .. IMAGE_TYPE_ALT .. "$",
      no_body = true, query = jf_image_query() },
    { name="musicgenres images by index", method="GET",
      path = "^/MusicGenres/[^/\\x00-\\x1f]{1,200}/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+$",
      no_body = true, query = jf_image_query() },
    { name="persons images by type", method="GET",
      path = "^/Persons/[^/\\x00-\\x1f]{1,200}/Images/" .. IMAGE_TYPE_ALT .. "$",
      no_body = true, query = jf_image_query() },
    { name="persons images by index", method="GET",
      path = "^/Persons/[^/\\x00-\\x1f]{1,200}/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+$",
      no_body = true, query = jf_image_query() },
    { name="studios images by type", method="GET",
      path = "^/Studios/[^/\\x00-\\x1f]{1,200}/Images/" .. IMAGE_TYPE_ALT .. "$",
      no_body = true, query = jf_image_query() },
    { name="studios images by index", method="GET",
      path = "^/Studios/[^/\\x00-\\x1f]{1,200}/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+$",
      no_body = true, query = jf_image_query() },

    -- Current-user avatar (?userId= query, defaults to the authenticated
    -- user - GetUserImage/PostUserImage/DeleteUserImage) and the
    -- [Obsolete but still live] per-userId-path-segment legacy form
    -- (GetUserImageLegacy/PostUserImageLegacy/DeleteUserImageLegacy, plus
    -- their /{index} variants, all delegating to the same handlers). Split
    -- by method, not combined like the item-image routes above - GET/POST/
    -- DELETE each bind a genuinely different query param set here (GET
    -- takes tag/format, POST/DELETE take neither), and POST needs a real
    -- image body while GET/DELETE must not have one.
    { name="user image get", method="GET", path=[[^/UserImage$]], no_body = true,
      query = T.object({
        userId = T.nullable(jf_id()),
        tag    = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        format = T.nullable(T.string({ max = 8, enum = IMAGE_FORMAT_ENUM })),
      }) },
    { name="user image set", method="POST", path=[[^/UserImage$]],
      content_types = IMAGE_CONTENT_TYPES,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    { name="user image delete", method="DELETE", path=[[^/UserImage$]], no_body = true,
      query = T.object({ userId = T.nullable(jf_id()) }) },

    { name="users image legacy get", method="GET",
      path = "^/Users/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "$", no_body = true,
      query = jf_image_query() },
    { name="users image legacy set", method="POST",
      path = "^/Users/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "$",
      content_types = IMAGE_CONTENT_TYPES },
    { name="users image legacy delete", method="DELETE",
      path = "^/Users/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "$", no_body = true,
      query = T.object({ index = T.nullable(T.number_query({ integer = true, min = 0, max = 999 })) }) },
    { name="users image legacy by index get", method="GET",
      path = "^/Users/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+$", no_body = true,
      query = jf_image_query() },
    { name="users image legacy by index set", method="POST",
      path = "^/Users/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+$",
      content_types = IMAGE_CONTENT_TYPES },
    { name="users image legacy by index delete", method="DELETE",
      path = "^/Users/" .. ID .. "/Images/" .. IMAGE_TYPE_ALT .. "/[0-9]+$", no_body = true },

    -- Branding/Splashscreen: GET is public (no auth), POST/DELETE need
    -- RequiresElevation - all three still just need route coverage here,
    -- the WAF doesn't model authorization tiers.
    { name="branding splashscreen", methods={"GET","DELETE"}, path=[[^/Branding/Splashscreen$]], no_body=true },
    { name="branding splashscreen upload", method="POST", path=[[^/Branding/Splashscreen$]],
      content_types = IMAGE_CONTENT_TYPES },

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
    -- LyricsController: GET/DELETE (GetLyrics/DeleteLyrics) take no params
    -- at all; POST (UploadLyrics) takes ?fileName= (required) and a raw
    -- text/plain body (the lyric file itself, not JSON) - split per method
    -- since the shapes genuinely differ.
    { name="audio lyrics",        methods={"GET","DELETE"}, path="^/Audio/" .. ID .. "/Lyrics$", no_body=true },
    { name="audio lyrics upload", method="POST", path="^/Audio/" .. ID .. "/Lyrics$",
      content_types = { "text/plain" },
      query = T.object({ fileName = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }) },
        { required = { fileName = true } }) },
    { name="audio lyrics remote", method="GET",                    path="^/Audio/" .. ID .. "/RemoteSearch/Lyrics$", no_body=true },
    { name="audio lyrics remote download", method="POST", path="^/Audio/" .. ID .. "/RemoteSearch/Lyrics/" .. OPAQUE_ID .. "$", no_body=true },
    { name="providers lyrics get", method="GET", path="^/Providers/Lyrics/" .. OPAQUE_ID .. "$", no_body=true },
    -- AudioController.GetAudioStream/GetAudioStreamByContainer: full query
    -- schema via the shared jf_stream_query() helper (see its definition
    -- near the top of this file for the evidence/rationale).
    { name="audio stream",     method="GET", path="^/Audio/" .. ID .. "/stream$", no_body=true,
      query = jf_stream_query(false) },
    { name="audio stream ext", method="GET", path="^/Audio/" .. ID .. "/stream\\.[A-Za-z0-9]{1,10}$", no_body=true,
      query = jf_stream_query(false) },
    -- UniversalAudioController.GetUniversalAudioStream: adaptive-streaming
    -- endpoint most mobile/TV clients use for audio playback in preference
    -- to plain /stream - its own distinct (smaller) query param set.
    { name="audio universal",  method="GET", path="^/Audio/" .. ID .. "/universal$", no_body=true,
      query = T.object({
        container                 = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
        mediaSourceId              = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        deviceId                   = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        userId                     = T.nullable(jf_id()),
        audioCodec                 = T.nullable(T.string({ max = 40, match = "^" .. CONTAINER_RE .. "$" })),
        maxAudioChannels           = T.nullable(T.number_query({ integer = true, min = 0 })),
        transcodingAudioChannels   = T.nullable(T.number_query({ integer = true, min = 0 })),
        maxStreamingBitrate        = T.nullable(T.number_query({ integer = true, min = 0 })),
        audioBitRate               = T.nullable(T.number_query({ integer = true, min = 0 })),
        startTimeTicks             = T.nullable(T.number_query({ integer = true, min = 0 })),
        transcodingContainer       = T.nullable(T.string({ max = 40, match = "^" .. CONTAINER_RE .. "$" })),
        transcodingProtocol        = T.nullable(T.string({ max = 8, enum = { http=true, hls=true } })),
        maxAudioSampleRate         = T.nullable(T.number_query({ integer = true, min = 0 })),
        maxAudioBitDepth           = T.nullable(T.number_query({ integer = true, min = 0 })),
        enableRemoteMedia          = T.nullable(T.bool_query()),
        enableAudioVbrEncoding     = T.nullable(T.bool_query()),
        breakOnNonKeyFrames        = T.nullable(T.bool_query()),
        enableRedirection          = T.nullable(T.bool_query()),
      }) },

    -------------------------------------------------------------------------
    -- Videos / videos (lowercase used for HLS streaming segments)
    -------------------------------------------------------------------------
    -- Bare GET/POST /Videos doesn't exist anywhere on the real server
    -- (grepped every controller for HttpGet("Videos")/HttpPost("Videos") -
    -- only VideoAttachmentsController's [Route("Videos")] class-level
    -- prefix, whose own actions all require further path segments below) -
    -- this used to accept both with zero schema, a real gap in the
    -- deny-by-default direction.
    -- HlsSegmentController.StopEncodingProcess: both query params required.
    { name="videos active enc",    method="DELETE",        path=[[^/Videos/ActiveEncodings$]], no_body=true,
      query = T.object({
        deviceId      = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }),
        playSessionId = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }),
      }, { required = { deviceId = true, playSessionId = true } }) },
    -- HlsSegmentController.cs's own capitalized "/Videos/.../hls/{playlistId}/..."
    -- routes - a genuinely different real endpoint pair from the lowercase
    -- "/videos/.../hls1/main/..." ones covered further below (those are
    -- DynamicHlsController's; confirmed distinct by source, not a case
    -- variant of the same thing - both are real and both need coverage).
    { name="hls playlist legacy", method="GET",
      path = "^/Videos/" .. ID .. "/hls/" .. OPAQUE_ID .. "/stream\\.m3u8$", no_body=true },
    { name="hls segment legacy",  method="GET",
      path = "^/Videos/" .. ID .. "/hls/" .. OPAQUE_ID .. "/" .. OPAQUE_ID .. "\\.[a-zA-Z0-9\\-._,|]{0,40}$", no_body=true },
    -- SubtitleController.UploadSubtitle: Data is base64-encoded subtitle
    -- file content, so no fixed length bound like other free-text fields -
    -- max_body already caps the whole request.
    { name="videos subtitles",     method="POST",          path="^/Videos/" .. ID .. "/Subtitles$",
      content_types = { "application/json" },
      json = T.object({
        Language          = T.string({ max = 16, not_match = "[\\x00-\\x1f]" }),
        Format            = T.string({ max = 16, not_match = "[\\x00-\\x1f]" }),
        IsForced          = T.boolean(),
        IsHearingImpaired = T.boolean(),
        Data              = T.string({ max = 8 * 1024 * 1024, not_match = "[\\x00-\\x1f]" }),
      }, { required = { Language = true, Format = true, IsForced = true, IsHearingImpaired = true, Data = true } }) },
    -- VideosController.cs: /Videos/{itemId}/stream is [HttpGet]+[HttpHead] only -
    -- no POST variant exists anywhere in the real API ("videos stream post" above
    -- this comment used to model one; removed, GET/HEAD is covered below).
    -- VideosController.GetVideoStream: full query schema via the shared
    -- jf_stream_query(true) helper (video adds maxWidth/maxHeight vs audio).
    { name="videos stream get",    method="GET",           path="^/Videos/" .. ID .. "/stream$", no_body=true,
      query = jf_stream_query(true) },
    -- {container} is a free-form route segment server-side (EncodingHelper.
    -- ContainerValidationRegexStr, same pattern as LiveStreamFiles' - not
    -- just mp4/mkv/webm; a real gap, any other supported container (ts,
    -- m4v, avi, mov, ...) would have been blocked.
    -- GetVideoStreamByContainer: same query set as "videos stream get" -
    -- {container} is a path segment here, but the query key is harmless to
    -- also allow (some client library revisions send both).
    { name="videos stream container", method="GET",
      path = "^/Videos/" .. ID .. "/stream\\.[a-zA-Z0-9\\-._,|]{0,40}$", no_body=true,
      query = jf_stream_query(true) },
    { name="videos additionalparts", method="GET", path="^/Videos/" .. ID .. "/AdditionalParts$", no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    { name="videos alternatesources delete", method="DELETE", path="^/Videos/" .. ID .. "/AlternateSources$", no_body=true },
    { name="videos mergeversions", method="POST", path=[[^/Videos/MergeVersions$]], no_body=true,
      query = T.object({ ids = T.string({ max = 65536, not_match = "[\\x00-\\x1f]" }) },
                        { required = { ids = true } }) },
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
    -- SubtitleController.DownloadRemoteSubtitles: itemId+subtitleId both
    -- path segments, no query/body params at all.
    { name="items subtitle download", method="POST", path="^/Items/" .. ID .. "/RemoteSearch/Subtitles/" .. OPAQUE_ID .. "$", no_body=true },
    { name="subtitle remote get", method="GET", path="^/Providers/Subtitles/Subtitles/" .. OPAQUE_ID .. "$", no_body=true },
    -- subtitles.m3u8: HLS playlist form of the subtitle stream, same
    -- route/query shape as the Stream.{format} routes above (index/
    -- mediaSourceId as path segments here, no query-based legacy fallback).
    { name="videos subtitle m3u8", method="GET",
      path = "^/Videos/" .. ID .. "/" .. OPAQUE_ID .. "/Subtitles/[0-9]+/subtitles\\.m3u8$", no_body=true,
      query = T.object({
        endPositionTicks   = T.nullable(T.number_query({ integer = true, min = 0, max = 1e13 })),
        copyTimestamps     = T.nullable(T.bool_query()),
        addVttTimeMap      = T.nullable(T.bool_query()),
        startPositionTicks = T.nullable(T.number_query({ integer = true, min = 0, max = 1e13 })),
      }) },
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
    -- DynamicHlsController.cs's own real route attributes are capitalized
    -- "/Videos/"|"/Audio/" (unlike the lowercase forms above, confirmed by
    -- an earlier audit as what's actually used) - these HLS URLs are built
    -- by the external @jellyfin/sdk npm package, not vendored in
    -- app-sources/, so the real casing can't be confirmed from source the
    -- way the lowercase forms were. Added alongside (not replacing) the
    -- already-verified lowercase routes, at the same permissive no_body/
    -- no-query-schema level already established for this route class -
    -- transcoding playback is exactly the wrong place to guess at a strict
    -- query schema and risk a false positive.
    {
      name    = "hls playlist capitalized",
      method  = "GET",
      paths   = {
        "^/Videos/" .. ID .. "/(?:master|main|live)\\.m3u8$",
        "^/Audio/" .. ID .. "/(?:master|main)\\.m3u8$",
      },
      no_body = true,
    },
    {
      name    = "hls segments capitalized",
      method  = "GET",
      paths   = {
        "^/Videos/" .. ID .. "/hls1/" .. OPAQUE_ID .. "/" .. OPAQUE_ID .. "\\.[a-zA-Z0-9\\-._,|]{0,40}$",
        "^/Audio/" .. ID .. "/hls1/" .. OPAQUE_ID .. "/" .. OPAQUE_ID .. "\\.[a-zA-Z0-9\\-._,|]{0,40}$",
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
    -- GetSessions: no POST /Sessions exists anywhere on the real server
    -- (only [HttpGet("Sessions")]) - the previous methods={"GET","POST"}
    -- here accepted a fictional POST with zero schema on either leg.
    { name="sessions", method="GET", path=[[^/Sessions$]], no_body=true,
      query = T.object({
        controllableByUserId = T.nullable(jf_id()),
        deviceId              = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        activeWithinSeconds   = T.nullable(T.number_query({ integer = true, min = 0 })),
      }) },
    -- PostCapabilities: query params only, no body at all.
    { name="sessions capabilities",    method="POST", path=[[^/Sessions/Capabilities$]], no_body=true,
      query = T.object({
        id                           = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        playableMediaTypes           = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        supportedCommands            = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
        supportsMediaControl         = T.nullable(T.bool_query()),
        supportsPersistentIdentifier = T.nullable(T.bool_query()),
      }) },
    -- PostFullCapabilities: ?id= query + ClientCapabilitiesDto body.
    -- .DeviceProfile is the same MediaBrowser.Model.Dlna.DeviceProfile
    -- flagged elsewhere in this file (T.any(), see jf_playback_info_dto's
    -- comment) - every other field is typed.
    { name="sessions capabilities full",method="POST", path=[[^/Sessions/Capabilities/Full$]],
      content_types = { "application/json" },
      query = T.object({ id = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })) }),
      json = T.object({
        PlayableMediaTypes           = T.nullable(T.array(T.string({ max = 16,
          enum = { Unknown=true, Video=true, Audio=true, Photo=true, Book=true } }), { max = 8 })),
        SupportedCommands            = T.nullable(T.array(T.string({ max = 32, enum = GENERAL_COMMAND_ENUM }), { max = 64 })),
        SupportsMediaControl         = T.nullable(T.boolean()),
        SupportsPersistentIdentifier = T.nullable(T.boolean()),
        DeviceProfile                = T.any(),
        AppStoreUrl                  = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
        IconUrl                      = T.nullable(T.string({ max = 2048, not_match = "[\\x00-\\x1f]" })),
      }) },
    -- SendMessageCommand: body is MessageCommand {Header, Text, TimeoutMs}.
    -- sessionId is `[FromRoute] string`, not a Guid (same as every other
    -- Sessions/{sessionId}/... route in this section) - the previous `ID`
    -- pattern here was a real gap: any non-Guid-shaped real session id
    -- (OPAQUE_ID is what every sibling route below already uses) would have
    -- been blocked.
    { name="sessions message",         method="POST",          path="^/Sessions/" .. OPAQUE_ID .. "/Message$",
      content_types = { "application/json" },
      json = T.object({
        Header    = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
        Text      = T.string({ max = 4096, not_match = "[\\x00-\\x1f]" }),
        TimeoutMs = T.nullable(T.number({ integer = true, min = 0 })),
      }, { required = { Text = true } }) },
    -- Full audit against real source (SessionController.cs), not just
    -- live-reported false positives.
    { name="sessions viewing (session)", method="POST", path="^/Sessions/" .. OPAQUE_ID .. "/Viewing$", no_body=true,
      query = T.object({
        itemType = T.string({ max = 32, enum = BASE_ITEM_KIND_ENUM }),
        itemId   = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
        itemName = T.string({ max = 1024, not_match = "[\\x00-\\x1f]" }),
      }, { required = { itemType = true, itemId = true, itemName = true } }) },
    { name="sessions system command", method="POST",
      path = "^/Sessions/" .. OPAQUE_ID .. "/System/" .. GENERAL_COMMAND_ALT .. "$", no_body = true },
    { name="sessions general command", method="POST",
      path = "^/Sessions/" .. OPAQUE_ID .. "/Command/" .. GENERAL_COMMAND_ALT .. "$", no_body = true },
    { name="sessions user add",    method="POST",   path="^/Sessions/" .. OPAQUE_ID .. "/User/" .. ID .. "$", no_body=true },
    { name="sessions user remove", method="DELETE", path="^/Sessions/" .. OPAQUE_ID .. "/User/" .. ID .. "$", no_body=true },
    { name="sessions viewing",     method="POST",   path=[[^/Sessions/Viewing$]], no_body=true,
      query = T.object({
        sessionId = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        itemId    = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
      }, { required = { itemId = true } }) },
    { name="sessions logout",      method="POST",   path=[[^/Sessions/Logout$]], no_body=true },
    -- Remote-control commands (SessionController.cs) - unlike the comment
    -- that used to sit here claimed, every one of these IS in the vendored
    -- server source (the "jellyfin-apiclient" npm package affects only what
    -- values a given client chooses to *send*, not the server-side [FromQuery]/
    -- [FromBody] param names it binds against, which come from the C#
    -- controller itself). Query-param casing/shape confirmed directly
    -- against SessionController.Play/SendPlaystateCommand/SendFullGeneralCommand.
    {
      -- SessionController.Play: playCommand+itemIds required; comma-
      -- delimited Guid[] for itemIds (CommaDelimitedCollectionModelBinder).
      name    = "sessions playing (session)",
      method  = "POST",
      path    = "^/Sessions/" .. OPAQUE_ID .. "/Playing$",
      no_body = true,
      query   = T.object({
        playCommand          = T.string({ max = 16, enum = PLAY_COMMAND_ENUM }),
        itemIds              = T.string({ max = 65536, not_match = "[\\x00-\\x1f]" }),
        startPositionTicks   = T.nullable(T.number_query({ integer = true, min = 0 })),
        mediaSourceId        = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        audioStreamIndex     = T.nullable(T.number_query({ integer = true })),
        subtitleStreamIndex  = T.nullable(T.number_query({ integer = true })),
        startIndex           = T.nullable(T.number_query({ integer = true, min = 0 })),
      }, { required = { playCommand = true, itemIds = true } }),
    },
    {
      -- SessionController.SendPlaystateCommand: {command} is the path
      -- segment (already PLAYSTATE_COMMAND below); both query params optional.
      name    = "sessions playing command",
      method  = "POST",
      path    = "^/Sessions/" .. OPAQUE_ID .. "/Playing/" .. PLAYSTATE_COMMAND .. "$",
      no_body = true,
      query   = T.object({
        seekPositionTicks  = T.nullable(T.number_query({ integer = true, min = 0 })),
        controllingUserId  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
      }),
    },
    -- SessionController.SendFullGeneralCommand: body is GeneralCommand
    -- {Name, ControllingUserId, Arguments} - Arguments is a free-form
    -- Dictionary<string,string> (command-specific key/value pairs, e.g.
    -- DisplayMessage's Header/Text/TimeoutMs, SetVolume's Volume, ...) - not
    -- a fixed schema, same posture as jf_provider_list()'s dynamic-name
    -- lists elsewhere in this file.
    {
      name   = "sessions command",
      method = "POST",
      path   = "^/Sessions/" .. OPAQUE_ID .. "/Command$",
      content_types = { "application/json" },
      json = T.object({
        Name              = T.string({ max = 32, enum = GENERAL_COMMAND_ENUM }),
        ControllingUserId = T.nullable(jf_id()),
        Arguments         = T.nullable(T.dict(T.string({ max = 4096, not_match = "[\\x00-\\x1f]" }))),
      }, { required = { Name = true } }),
    },
    -- PlaystateController.ReportPlaybackStart/ReportPlaybackProgress: see
    -- jf_playback_report_fields()'s big comment above for why this accepts
    -- several fields with no C# model equivalent.
    { name="sessions playing",         method="POST",          path=[[^/Sessions/Playing$]],
      content_types = { "application/json" },
      json = T.object(jf_playback_report_fields()) },
    { name="sessions playing progress",method="POST",          path=[[^/Sessions/Playing/Progress$]],
      content_types = { "application/json" },
      json = T.object(jf_playback_report_fields({ event_name = true })) },
    -- "Stop" (as opposed to "Stopped" below) doesn't exist anywhere in real
    -- PlaystateController.cs - left as-is rather than removed (harmless:
    -- matches nothing a real client sends, real server would 404 it too),
    -- but no_body since nothing would ever legitimately post one here.
    { name="sessions playing stop",    method="POST",          path=[[^/Sessions/Playing/Stop$]], no_body=true },
    -- PlaystateController.ReportPlaybackStopped: same PlayState-blob spread
    -- as the other two (see jf_playback_report_fields() above), plus
    -- Failed/NextMediaType which only ever appear on this call.
    { name="sessions playing stopped", method="POST",          path=[[^/Sessions/Playing/Stopped$]],
      content_types = { "application/json" },
      json = T.object(jf_playback_report_fields({ stop_only = true })) },
    -- PingPlaybackSession - real gap, found via full audit against source.
    { name="sessions playing ping",    method="POST",          path=[[^/Sessions/Playing/Ping$]], no_body=true,
      query = T.object({ playSessionId = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }) },
                        { required = { playSessionId = true } }) },

    -- PlayingItems (OnPlaybackStart/Progress/Stopped) - the older, all-
    -- [Obsolete]-but-still-live query-param-based playback-reporting API,
    -- superseded by the Sessions/Playing/* JSON-body form above but still
    -- used by older/simpler clients. Completely unrouted before this pass.
    { name="playingitems start", method="POST", path="^/PlayingItems/" .. ID .. "$", no_body=true,
      query = T.object({
        mediaSourceId       = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        audioStreamIndex    = T.nullable(T.number_query({ integer = true, min = 0, max = 1000 })),
        subtitleStreamIndex = T.nullable(T.number_query({ integer = true, min = 0, max = 1000 })),
        playMethod          = T.nullable(T.string({ max = 16, enum = { Transcode=true, DirectStream=true, DirectPlay=true } })),
        liveStreamId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        playSessionId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        canSeek                = T.nullable(T.bool_query()),
      }) },
    { name="users playingitems start", method="POST", path="^/Users/" .. ID .. "/PlayingItems/" .. ID .. "$", no_body=true,
      query = T.object({
        mediaSourceId       = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        audioStreamIndex    = T.nullable(T.number_query({ integer = true, min = 0, max = 1000 })),
        subtitleStreamIndex = T.nullable(T.number_query({ integer = true, min = 0, max = 1000 })),
        playMethod          = T.nullable(T.string({ max = 16, enum = { Transcode=true, DirectStream=true, DirectPlay=true } })),
        liveStreamId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        playSessionId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        canSeek                = T.nullable(T.bool_query()),
      }) },
    { name="playingitems progress", method="POST", path="^/PlayingItems/" .. ID .. "/Progress$", no_body=true,
      query = T.object({
        mediaSourceId       = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        positionTicks        = T.nullable(T.number_query({ integer = true, min = 0, max = 1e13 })),
        audioStreamIndex    = T.nullable(T.number_query({ integer = true, min = 0, max = 1000 })),
        subtitleStreamIndex = T.nullable(T.number_query({ integer = true, min = 0, max = 1000 })),
        volumeLevel           = T.nullable(T.number_query({ integer = true, min = 0, max = 100 })),
        playMethod          = T.nullable(T.string({ max = 16, enum = { Transcode=true, DirectStream=true, DirectPlay=true } })),
        liveStreamId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        playSessionId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        repeatMode             = T.nullable(T.string({ max = 16, enum = { RepeatNone=true, RepeatAll=true, RepeatOne=true } })),
        isPaused                = T.nullable(T.bool_query()),
        isMuted                 = T.nullable(T.bool_query()),
      }) },
    { name="users playingitems progress", method="POST", path="^/Users/" .. ID .. "/PlayingItems/" .. ID .. "/Progress$", no_body=true,
      query = T.object({
        mediaSourceId       = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        positionTicks        = T.nullable(T.number_query({ integer = true, min = 0, max = 1e13 })),
        audioStreamIndex    = T.nullable(T.number_query({ integer = true, min = 0, max = 1000 })),
        subtitleStreamIndex = T.nullable(T.number_query({ integer = true, min = 0, max = 1000 })),
        volumeLevel           = T.nullable(T.number_query({ integer = true, min = 0, max = 100 })),
        playMethod          = T.nullable(T.string({ max = 16, enum = { Transcode=true, DirectStream=true, DirectPlay=true } })),
        liveStreamId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        playSessionId         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        repeatMode             = T.nullable(T.string({ max = 16, enum = { RepeatNone=true, RepeatAll=true, RepeatOne=true } })),
        isPaused                = T.nullable(T.bool_query()),
        isMuted                 = T.nullable(T.bool_query()),
      }) },
    { name="playingitems stop",  method="DELETE", path="^/PlayingItems/" .. ID .. "$", no_body=true,
      query = T.object({
        mediaSourceId  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        nextMediaType   = T.nullable(T.string({ max = 64,  not_match = "[\\x00-\\x1f]" })),
        positionTicks   = T.nullable(T.number_query({ integer = true, min = 0, max = 1e13 })),
        liveStreamId    = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        playSessionId   = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
      }) },
    { name="users playingitems stop", method="DELETE", path="^/Users/" .. ID .. "/PlayingItems/" .. ID .. "$", no_body=true,
      query = T.object({
        mediaSourceId  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        nextMediaType   = T.nullable(T.string({ max = 64,  not_match = "[\\x00-\\x1f]" })),
        positionTicks   = T.nullable(T.number_query({ integer = true, min = 0, max = 1e13 })),
        liveStreamId    = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        playSessionId   = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
      }) },

    -------------------------------------------------------------------------
    -- SyncPlay
    -------------------------------------------------------------------------
    -- Full audit against real source (SyncPlayController.cs + every
    -- Jellyfin.Api/Models/SyncPlayDtos/*.cs), not just live-reported false
    -- positives - only 6 of ~21 real actions had any coverage before this
    -- pass (group-watch is a real, actively-used feature). Every DTO here
    -- is [FromBody, Required] (the body itself must be present) but none of
    -- their individual properties carry their own [Required] - an omitted
    -- field just gets silently defaulted (Guid.Empty/0/false) by JSON
    -- deserialization, so every field is nullable rather than required,
    -- matching the syncplay buffering route's existing precedent below.
    { name="syncplay list",       method="GET",  path=[[^/SyncPlay/List$]],       no_body=true },
    { name="syncplay group",      method="GET",  path="^/SyncPlay/" .. ID .. "$", no_body=true },
    { name="syncplay new",        method="POST", path=[[^/SyncPlay/New$]],
      content_type = "application/json",
      json = T.object({ groupName = T.nullable(T.string({ max = 200, not_match = "[\\x00-\\x1f]" })) }) },
    { name="syncplay join",       method="POST", path=[[^/SyncPlay/Join$]],
      content_type = "application/json",
      json = T.object({ groupId = T.nullable(T.uuid()) }) },
    { name="syncplay leave",      method="POST", path=[[^/SyncPlay/Leave$]],      no_body=true },
    { name="syncplay setnewqueue", method="POST", path=[[^/SyncPlay/SetNewQueue$]],
      content_type = "application/json",
      json = T.object({
        playingQueue        = T.nullable(T.array(T.uuid(), { max = 10000 })),
        playingItemPosition  = T.nullable(T.number({ integer = true, min = 0, max = 10000 })),
        startPositionTicks   = T.nullable(T.number({ integer = true, min = 0, max = 1e13 })),
      }) },
    { name="syncplay setplaylistitem", method="POST", path=[[^/SyncPlay/SetPlaylistItem$]],
      content_type = "application/json",
      json = T.object({ playlistItemId = T.nullable(T.uuid()) }) },
    { name="syncplay removefromplaylist", method="POST", path=[[^/SyncPlay/RemoveFromPlaylist$]],
      content_type = "application/json",
      json = T.object({
        playlistItemIds  = T.nullable(T.array(T.uuid(), { max = 10000 })),
        clearPlaylist    = T.nullable(T.boolean()),
        clearPlayingItem = T.nullable(T.boolean()),
      }) },
    { name="syncplay moveplaylistitem", method="POST", path=[[^/SyncPlay/MovePlaylistItem$]],
      content_type = "application/json",
      json = T.object({
        playlistItemId = T.nullable(T.uuid()),
        newIndex       = T.nullable(T.number({ integer = true, min = 0, max = 10000 })),
      }) },
    { name="syncplay queue",      method="POST", path=[[^/SyncPlay/Queue$]],
      content_type = "application/json",
      json = T.object({
        itemIds = T.nullable(T.array(T.uuid(), { max = 10000 })),
        mode    = T.nullable(T.string({ max = 16, enum = { Queue=true, QueueNext=true } })),
      }) },
    { name="syncplay unpause",    method="POST", path=[[^/SyncPlay/Unpause$]],    no_body=true },
    -- Confirmed via live-test against a real server (offline mock testing can't
    -- catch a method mismatch): SyncPlayController.cs has [HttpPost("Pause")]
    -- and [HttpPost("Buffering")] - GET 405s. Pause takes no params at all
    -- (SyncPlayPause(), no [FromBody]); Buffering requires a BufferRequestDto body.
    { name="syncplay pause",      method="POST", path=[[^/SyncPlay/Pause$]],      no_body=true },
    { name="syncplay stop",       method="POST", path=[[^/SyncPlay/Stop$]],       no_body=true },
    { name="syncplay seek",       method="POST", path=[[^/SyncPlay/Seek$]],
      content_type = "application/json",
      json = T.object({ positionTicks = T.nullable(T.number({ integer=true, min=0, max=1e13 })) }) },
    { name="syncplay buffering",  method="POST", path=[[^/SyncPlay/Buffering$]],
      content_type = "application/json",
      -- BufferRequestDto (Jellyfin.Api/Models/SyncPlayDtos/BufferRequestDto.cs):
      -- [FromBody, Required] marks the body itself as required, but none of its
      -- four properties carry their own [Required] - a client omitting one just
      -- gets silently defaulted (Guid.Empty / 0 / false) by JSON deserialization,
      -- so every field here is nullable rather than required.
      json = T.object({
        when             = T.nullable(T.iso8601()),
        positionTicks    = T.nullable(T.number({ integer=true, min=0, max=1e13 })),  -- 100ns units; 1e13 ~= 278 hours, generous headroom
        isPlaying        = T.nullable(T.boolean()),
        playlistItemId   = T.nullable(T.uuid()),
      }) },
    { name="syncplay ready",      method="POST", path=[[^/SyncPlay/Ready$]],
      content_type = "application/json",
      json = T.object({
        when           = T.nullable(T.iso8601()),
        positionTicks  = T.nullable(T.number({ integer=true, min=0, max=1e13 })),
        isPlaying      = T.nullable(T.boolean()),
        playlistItemId = T.nullable(T.uuid()),
      }) },
    { name="syncplay setignorewait", method="POST", path=[[^/SyncPlay/SetIgnoreWait$]],
      content_type = "application/json",
      json = T.object({ ignoreWait = T.nullable(T.boolean()) }) },
    { name="syncplay nextitem",   method="POST", path=[[^/SyncPlay/NextItem$]],
      content_type = "application/json",
      json = T.object({ playlistItemId = T.nullable(T.uuid()) }) },
    { name="syncplay previousitem", method="POST", path=[[^/SyncPlay/PreviousItem$]],
      content_type = "application/json",
      json = T.object({ playlistItemId = T.nullable(T.uuid()) }) },
    { name="syncplay setrepeatmode", method="POST", path=[[^/SyncPlay/SetRepeatMode$]],
      content_type = "application/json",
      json = T.object({ mode = T.nullable(T.string({ max = 16,
        enum = { RepeatOne=true, RepeatAll=true, RepeatNone=true } })) }) },
    { name="syncplay setshufflemode", method="POST", path=[[^/SyncPlay/SetShuffleMode$]],
      content_type = "application/json",
      json = T.object({ mode = T.nullable(T.string({ max = 16, enum = { Sorted=true, Shuffle=true } })) }) },
    { name="syncplay ping",       method="POST", path=[[^/SyncPlay/Ping$]],
      content_type = "application/json",
      json = T.object({ ping = T.nullable(T.number({ integer=true, min=0, max=1e13 })) }) },

    -------------------------------------------------------------------------
    -- Live TV
    -------------------------------------------------------------------------
    -- Full audit against real source (LiveTvController.cs), not just live-
    -- reported false positives - only 6 of 41 real actions had any coverage
    -- before this pass. GetProgramsDto/GetLiveTvPrograms' many-optional-
    -- filter-field query DTOs still follow this file's content-type-only
    -- precedent for genuinely huge shapes; TimerInfoDto/SeriesTimerInfoDto
    -- turned out tractable on a closer look (see jf_timer_info_dto below)
    -- and are now fully typed instead.
    { name="livetv info",         method="GET",          path=[[^/LiveTv/Info$]],                                   no_body=true },
    { name="livetv guideinfo",    method="GET",          path=[[^/LiveTv/GuideInfo$]],                              no_body=true },
    -- AddTunerHost (POST, TunerHostInfo body) / DeleteTunerHost (DELETE,
    -- ?id= query) - genuinely different shapes per method, split accordingly.
    { name="livetv tunerhosts add",    method="POST",   path=[[^/LiveTv/TunerHosts$]],
      content_types = { "application/json" }, json = jf_tuner_host_info },
    { name="livetv tunerhosts delete", method="DELETE", path=[[^/LiveTv/TunerHosts$]], no_body=true,
      query = T.object({ id = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })) }) },
    { name="livetv tuner reset",  method="POST",         path="^/LiveTv/Tuners/" .. OPAQUE_ID .. "/Reset$",         no_body=true },
    { name="livetv listprov sd",  method="GET",          path=[[^/LiveTv/ListingProviders/SchedulesDirect/Countries$]], no_body=true },
    { name="livetv listprov def", method="GET",          path=[[^/LiveTv/ListingProviders/Default$]],              no_body=true },
    { name="livetv listprov",     method="POST",         path=[[^/LiveTv/ListingProviders$]],
      query = T.object({
        pw               = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        validateListings = T.nullable(T.bool_query()),
        validateLogin    = T.nullable(T.bool_query()),
      }) },
    { name="livetv listprov delete", method="DELETE",     path=[[^/LiveTv/ListingProviders$]], no_body=true,
      query = T.object({ id = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })) }) },
    { name="livetv listprov lineups", method="GET",       path=[[^/LiveTv/ListingProviders/Lineups$]], no_body=true,
      query = T.object({
        id       = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        type     = T.nullable(T.string({ max = 64,  not_match = "[\\x00-\\x1f]" })),
        location = T.nullable(T.string({ max = 128, not_match = "[\\x00-\\x1f]" })),
        country  = T.nullable(T.string({ max = 64,  not_match = "[\\x00-\\x1f]" })),
      }) },
    { name="livetv channelmap options", method="GET",     path=[[^/LiveTv/ChannelMappingOptions$]], no_body=true,
      query = T.object({ providerId = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })) }) },
    { name="livetv channelmap set", method="POST",        path=[[^/LiveTv/ChannelMappings$]],
      content_types = { "application/json" } },
    { name="livetv tuner types",  method="GET",          path=[[^/LiveTv/TunerHosts/Types$]],                      no_body=true },
    { name="livetv discover",     method="GET",          path=[[^/LiveTv/Tuners/Discover$]],                       no_body=true },
    { name="livetv channels",     method="GET",          path=[[^/LiveTv/Channels$]],                              no_body=true },
    { name="livetv channel by id",method="GET",          path="^/LiveTv/Channels/" .. ID .. "$",                   no_body=true },
    { name="livetv timers",       method="GET",          path=[[^/LiveTv/Timers$]],                                no_body=true,
      query = T.object({
        channelId     = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        seriesTimerId = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        isActive      = T.nullable(T.bool_query()),
        isScheduled   = T.nullable(T.bool_query()),
      }) },
    -- DVR timer CRUD (recordingeditor.js, recordinghelper.js). timerId is a
    -- `string` route param server-side (opaque, not GUID). GET/DELETE carry
    -- no body; POST (UpdateTimer/CreateTimer) binds TimerInfoDto - now fully
    -- typed via jf_timer_info_dto() (see its definition above).
    {
      name    = "livetv timer by id",
      methods = { "GET", "DELETE" },
      path    = "^/LiveTv/Timers/" .. OPAQUE_ID .. "$",
      no_body = true,
    },
    {
      name          = "livetv timer by id update",
      method        = "POST",
      path          = "^/LiveTv/Timers/" .. OPAQUE_ID .. "$",
      content_types = { "application/json" },
      json          = jf_timer_info_dto(),
    },
    {
      name          = "livetv timers create",
      method        = "POST",
      path          = [[^/LiveTv/Timers$]],
      content_types = { "application/json" },
      json          = jf_timer_info_dto(),
    },
    { name="livetv recordings",   method="GET",          path=[[^/LiveTv/Recordings$]],                            no_body=true },
    -- Both [Obsolete], both real handlers just `return new QueryResult<>()`
    -- (dead/no-op server-side, kept only so old clients don't 404) -
    -- GetRecordingsSeries/GetRecordingGroups.
    { name="livetv rec series",   method="GET",          path=[[^/LiveTv/Recordings/Series$]],                     no_body=true },
    { name="livetv rec groups",   method="GET",          path=[[^/LiveTv/Recordings/Groups$]],                     no_body=true },
    -- Obsolete + always 404s (GetRecordingGroup: `return NotFound();`) -
    -- routed anyway so a real client requesting it gets a clean 404 from
    -- the backend instead of a WAF block indistinguishable from a real gap.
    { name="livetv rec group by id", method="GET",       path="^/LiveTv/Recordings/Groups/" .. ID .. "$",          no_body=true },
    { name="livetv rec by id",    methods={"GET","DELETE"}, path="^/LiveTv/Recordings/" .. ID .. "$", no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    { name="livetv rec folders",  method="GET",          path=[[^/LiveTv/Recordings/Folders$]],                    no_body=true },
    { name="livetv series timers",method="GET",          path=[[^/LiveTv/SeriesTimers$]],                          no_body=true,
      query = T.object({
        sortBy    = T.nullable(T.string({ max = 32, not_match = "[\\x00-\\x1f]" })),
        sortOrder = T.nullable(T.string({ max = 16, enum = { Ascending=true, Descending=true } })),
      }) },
    -- Series-recording CRUD (seriesrecordingeditor.js, guide.js). Same
    -- opaque-timerId split as "livetv timer by id" above; body is
    -- SeriesTimerInfoDto via jf_series_timer_info_dto().
    {
      name    = "livetv seriestimer by id",
      methods = { "GET", "DELETE" },
      path    = "^/LiveTv/SeriesTimers/" .. OPAQUE_ID .. "$",
      no_body = true,
    },
    {
      name          = "livetv seriestimer by id update",
      method        = "POST",
      path          = "^/LiveTv/SeriesTimers/" .. OPAQUE_ID .. "$",
      content_types = { "application/json" },
      json          = jf_series_timer_info_dto(),
    },
    {
      name          = "livetv seriestimers create",
      method        = "POST",
      path          = [[^/LiveTv/SeriesTimers$]],
      content_types = { "application/json" },
      json          = jf_series_timer_info_dto(),
    },
    { name="livetv prog rec",     method="GET",          path=[[^/LiveTv/Programs/Recommended$]],                  no_body=true },
    { name="livetv programs",     method="GET",          path=[[^/LiveTv/Programs$]],                              no_body=true },
    -- GetProgramsDto mirrors GetLiveTvPrograms' own (many optional filters)
    -- query param set - content-type-only, same big-DTO precedent as above.
    { name="livetv programs query", method="POST",       path=[[^/LiveTv/Programs$]],
      content_types = { "application/json" } },
    { name="livetv program by id", method="GET",         path="^/LiveTv/Programs/" .. OPAQUE_ID .. "$", no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    { name="livetv rec stream",   method="GET",          path="^/LiveTv/LiveRecordings/" .. OPAQUE_ID .. "/stream$", no_body=true },
    { name="livetv stream file",  method="GET",
      path = "^/LiveTv/LiveStreamFiles/" .. OPAQUE_ID .. "/stream\\.[a-zA-Z0-9\\-._,|]{0,40}$", no_body=true },

    -------------------------------------------------------------------------
    -- Live Streams
    -------------------------------------------------------------------------
    -- No "LiveStreams/MediaInfo" route exists anywhere on the real server
    -- (only Open/Close below, grepped the whole Controllers/ tree) - this
    -- used to accept it with zero schema, a fictional-endpoint gap in the
    -- deny-by-default direction (same bug pattern as "items"/"videos" above).
    --
    -- OpenLiveStreamDto (OpenLiveStream, required to start playback of any
    -- tuner-based live channel): query keys confirmed PascalCase from the
    -- real web client (playbackmanager.js:536-567's getLiveStream(), the one
    -- caller in the vendored source - a raw apiClient.ajax() call, not the
    -- generated SDK, so it bypasses the SDK's usual camelCase convention).
    -- ASP.NET's [FromQuery] binding is case-insensitive server-side, so both
    -- the C# signature's own camelCase names and the web client's PascalCase
    -- are accepted here to cover any other real client (mobile/TV apps use
    -- the generated SDK, which follows the OpenAPI camelCase spec) without
    -- guessing which one a given client picks. .DeviceProfile in the body
    -- is the same huge MediaBrowser.Model.Dlna.DeviceProfile flagged
    -- elsewhere (see jf_stream_query's comment) - not exhaustively typed;
    -- .OpenToken is.
    { name="livestreams open",  method="POST", path=[[^/LiveStreams/Open$]],
      content_types = { "application/json" },
      query = T.object({
        openToken      = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
        userId         = T.nullable(jf_id()),          UserId         = T.nullable(jf_id()),
        playSessionId  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        PlaySessionId  = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        maxStreamingBitrate = T.nullable(T.number_query({ integer = true, min = 0 })),
        MaxStreamingBitrate = T.nullable(T.number_query({ integer = true, min = 0 })),
        startTimeTicks = T.nullable(T.number_query({ integer = true, min = 0 })),
        StartTimeTicks = T.nullable(T.number_query({ integer = true, min = 0 })),
        audioStreamIndex = T.nullable(T.number_query({ integer = true })),
        AudioStreamIndex = T.nullable(T.number_query({ integer = true })),
        subtitleStreamIndex = T.nullable(T.number_query({ integer = true })),
        SubtitleStreamIndex = T.nullable(T.number_query({ integer = true })),
        maxAudioChannels = T.nullable(T.number_query({ integer = true, min = 0 })),
        itemId         = T.nullable(jf_id()),           ItemId         = T.nullable(jf_id()),
        enableDirectPlay   = T.nullable(T.bool_query()),
        enableDirectStream = T.nullable(T.bool_query()), EnableDirectStream = T.nullable(T.bool_query()),
        alwaysBurnInSubtitleWhenTranscoding = T.nullable(T.bool_query()),
      }),
      -- OpenLiveStreamDto body - .DeviceProfile is T.any() (same posture as
      -- jf_playback_info_dto's), every other field typed.
      json = T.object({
        OpenToken            = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
        UserId               = T.nullable(jf_id()),
        PlaySessionId        = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        MaxStreamingBitrate  = T.nullable(T.number({ integer = true, min = 0 })),
        StartTimeTicks       = T.nullable(T.number({ integer = true, min = 0 })),
        AudioStreamIndex     = T.nullable(T.number({ integer = true })),
        SubtitleStreamIndex  = T.nullable(T.number({ integer = true })),
        MaxAudioChannels     = T.nullable(T.number({ integer = true, min = 0 })),
        ItemId               = T.nullable(jf_id()),
        EnableDirectPlay     = T.nullable(T.boolean()),
        EnableDirectStream   = T.nullable(T.boolean()),
        AlwaysBurnInSubtitleWhenTranscoding = T.nullable(T.boolean()),
        DeviceProfile        = T.any(),
        DirectPlayProtocols  = T.nullable(T.array(T.string({ max = 8,
          enum = { File=true, Http=true, Rtmp=true, Rtsp=true, Udp=true, Rtp=true, Ftp=true } }), { max = 8 })),
      }) },
    { name="livestreams close", method="POST", path=[[^/LiveStreams/Close$]], no_body=true,
      query = T.object({ liveStreamId = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }) },
        { required = { liveStreamId = true } }) },

    -------------------------------------------------------------------------
    -- Collections, Movies, Playlists
    -------------------------------------------------------------------------
    -- CreateCollection: query keys confirmed PascalCase via collectionEditor.js
    -- (Name/IsLocked/Ids - ParentId not sent by the web client but is a real
    -- optional server param, kept accepted).
    { name="collections",         method="POST",         path=[[^/Collections$]], no_body=true,
      query = T.object({
        Name     = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
        Ids      = T.nullable(T.string({ max = 8192, not_match = "[\\x00-\\x1f]" })),
        ParentId = T.nullable(jf_id()),
        IsLocked = T.nullable(T.bool_query()),
      }) },
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
    -- PlaylistsController.cs: bare /Playlists is [HttpPost] only (create) - GET
    -- only exists at /Playlists/{playlistId}, already the "playlists by id" route.
    -- CreatePlaylist: [ParameterObsolete] query (kept for back-compat, comma-
    -- delimited ids) OR a CreatePlaylistDto body - both accepted, query wins
    -- if both present. Body confirmed via playlisteditor.ts:96 (generated
    -- SDK call): Name/IsPublic/Ids(array)/UserId, PascalCase.
    { name="playlists",           method="POST",          path=[[^/Playlists$]],
      content_types = { "application/json" },
      query = T.object({
        name      = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
        ids       = T.nullable(T.string({ max = 65536, not_match = "[\\x00-\\x1f]" })),
        userId    = T.nullable(jf_id()),
        mediaType = T.nullable(T.string({ max = 16,
          enum = { Unknown=true, Video=true, Audio=true, Photo=true, Book=true } })),
      }),
      json = T.nullable(T.object({
        Name     = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
        Ids      = T.nullable(T.array(jf_id(), { max = 8192 })),
        UserId   = T.nullable(jf_id()),
        MediaType = T.nullable(T.string({ max = 16,
          enum = { Unknown=true, Video=true, Audio=true, Photo=true, Book=true } })),
        Users    = T.nullable(T.array(T.object({
          UserId  = T.nullable(jf_id()),
          CanEdit = T.nullable(T.boolean()),
        }), { max = 64 })),
        IsPublic = T.nullable(T.boolean()),
      })) },
    -- GetPlaylist (GET, no body) / UpdatePlaylist (POST, UpdatePlaylistDto
    -- body - same shape as CreatePlaylistDto minus UserId/MediaType) -
    -- split so the json schema only applies to the POST leg.
    { name="playlists by id",     method="GET",  path="^/Playlists/" .. ID .. "$", no_body=true },
    { name="playlists by id update", method="POST", path="^/Playlists/" .. ID .. "$",
      content_types = { "application/json" },
      json = T.object({
        Name     = T.nullable(T.string({ max = 1024, not_match = "[\\x00-\\x1f]" })),
        Ids      = T.nullable(T.array(jf_id(), { max = 8192 })),
        Users    = T.nullable(T.array(T.object({
          UserId  = T.nullable(jf_id()),
          CanEdit = T.nullable(T.boolean()),
        }), { max = 64 })),
        IsPublic = T.nullable(T.boolean()),
      }) },
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
      name    = "playlists items move",
      method  = "POST",
      path    = "^/Playlists/" .. OPAQUE_ID .. "/Items/" .. OPAQUE_ID .. "/Move/[0-9]+$",
      no_body = true,
    },
    { name="playlists users",     method="GET",           path="^/Playlists/" .. ID .. "/Users$",           no_body=true },
    { name="playlists users byid",method="GET",           path="^/Playlists/" .. ID .. "/Users/" .. ID .. "$", no_body=true },
    { name="playlists user update", method="POST", path="^/Playlists/" .. ID .. "/Users/" .. ID .. "$",
      content_type = "application/json",
      json = T.nullable(T.object({ CanEdit = T.nullable(T.boolean()) })) },
    { name="playlists user remove", method="DELETE", path="^/Playlists/" .. ID .. "/Users/" .. ID .. "$", no_body=true },

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
    -- Same "by name" shape as Artists/Genres/MusicGenres above -
    -- GetPerson([FromRoute] name, [FromQuery] userId).
    { name="persons by name", method="GET", path=[[^/Persons/[^/\x00-\x1f]{1,200}$]], no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
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
    { name="studios by name", method="GET", path=[[^/Studios/[^/\x00-\x1f]{1,200}$]], no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    { name="years",     method="GET", path=[[^/Years$]],     no_body=true },
    { name="trailers",  method="GET", path=[[^/Trailers$]],  no_body=true },
    { name="years by id", method="GET", path=[[^/Years/[0-9]{1,4}$]], no_body=true,
      query = T.object({ userId = T.nullable(jf_id()) }) },
    { name="channels",  method="GET", path=[[^/Channels$]],  no_body=true },
    { name="channels features",     method="GET", path=[[^/Channels/Features$]], no_body=true },
    { name="channels by id features", method="GET", path="^/Channels/" .. ID .. "/Features$", no_body=true },
    { name="channels by id items",  method="GET", path="^/Channels/" .. ID .. "/Items$", no_body=true },
    { name="channels items latest", method="GET", path=[[^/Channels/Items/Latest$]], no_body=true },
    { name="devices",   method="GET", path=[[^/Devices$]],   no_body=true },
    { name="devices info", method="GET", path=[[^/Devices/Info$]], no_body=true,
      query = T.object({ id = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }) }, { required = { id = true } }) },
    { name="devices options get", method="GET", path=[[^/Devices/Options$]], no_body=true,
      query = T.object({ id = T.string({ max = 256, not_match = "[\\x00-\\x1f]" }) }, { required = { id = true } }) },
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
    { name="tasks",        method="GET",  path=[[^/ScheduledTasks$]],                                 no_body=true,
      query = T.object({
        isHidden  = T.nullable(T.bool_query()),
        isEnabled = T.nullable(T.bool_query()),
      }) },
    { name="tasks by id",  method="GET",  path="^/ScheduledTasks/" .. HEX32 .. "$",                   no_body=true },
    -- StartTask: taskId path segment only, no query/body params at all.
    { name="tasks run",    method="POST", path="^/ScheduledTasks/Running/" .. HEX32 .. "$", no_body=true },
    { name="tasks stop",   method="DELETE", path="^/ScheduledTasks/Running/" .. HEX32 .. "$", no_body=true },
    { name="tasks triggers", method="POST", path="^/ScheduledTasks/" .. HEX32 .. "/Triggers$",
      content_type = "application/json" },

    -------------------------------------------------------------------------
    -- Quick Connect
    -------------------------------------------------------------------------
    -- InitiateQuickConnect: no params at all, POST or the [Obsolete] GET
    -- form right below.
    { name="quickconnect initiate", method="POST", path=[[^/QuickConnect/Initiate$]], no_body=true },
    -- [Obsolete] GET form of Initiate, "still available to avoid breaking
    -- compatibility" per its own doc comment - kept working, not removed.
    { name="quickconnect initiate legacy", method="GET", path=[[^/QuickConnect/Initiate$]], no_body=true },
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
    -- ClientLogController.LogFile: raw text/plain log upload, no query
    -- params - MaxDocumentSize (1,000,000 bytes) enforced server-side via
    -- [RequestSizeLimit], mirrored here as an explicit route-level max_body
    -- override (tighter than the app-wide 10MB default).
    { name="clientlog", method="POST", path=[[^/ClientLog/Document$]],
      content_types = { "text/plain" }, max_body = 1000000 },

    -------------------------------------------------------------------------
    -- Misc: Search, TimeSync, legacy UserViews, video attachments
    -------------------------------------------------------------------------
    -- SearchController.cs: [Route("Search/Hints")] class-level + bare
    -- [HttpGet] - many optional filters, searchTerm is the only required one.
    { name="search hints", method="GET", path=[[^/Search/Hints$]], no_body=true,
      query = T.object({
        startIndex        = T.nullable(T.number_query({ integer = true, min = 0 })),
        limit              = T.nullable(T.number_query({ integer = true, min = 0 })),
        userId             = T.nullable(jf_id()),
        searchTerm         = T.string({ max = 512, not_match = "[\\x00-\\x1f]" }),
        includeItemTypes   = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
        excludeItemTypes   = T.nullable(T.string({ max = 512, not_match = "[\\x00-\\x1f]" })),
        mediaTypes         = T.nullable(T.string({ max = 256, not_match = "[\\x00-\\x1f]" })),
        parentId           = T.nullable(jf_id()),
        isMovie            = T.nullable(T.bool_query()),
        isSeries           = T.nullable(T.bool_query()),
        isNews             = T.nullable(T.bool_query()),
        isKids             = T.nullable(T.bool_query()),
        isSports           = T.nullable(T.bool_query()),
        includePeople      = T.nullable(T.bool_query()),
        includeMedia       = T.nullable(T.bool_query()),
        includeGenres      = T.nullable(T.bool_query()),
        includeStudios     = T.nullable(T.bool_query()),
        includeArtists     = T.nullable(T.bool_query()),
      }, { required = { searchTerm = true } }) },
    { name="timesync", method="GET", path=[[^/GetUtcTime$]], no_body=true },
    -- [Obsolete] legacy path-segment form of "userviews" (bare) above.
    { name="users views legacy", method="GET", path="^/Users/" .. ID .. "/Views$", no_body=true },
    { name="video attachment", method="GET",
      path = "^/Videos/" .. ID .. "/" .. OPAQUE_ID .. "/Attachments/[0-9]+$", no_body=true },

  },
}
