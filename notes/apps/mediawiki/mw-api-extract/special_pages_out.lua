-- Write-capable Special: pages (Tier 6), heuristically extracted.
-- Candidate field NAMES only (no type info) - every field is a generously
-- capped nullable string; precision here is 'unknown fields are rejected',
-- not 'each field's exact shape is validated' (same treatment as the
-- EditPage index.php POST form above).

-- upload (Special:Upload, SpecialUpload) -- Specials/SpecialUpload.php
local upload_form = T.object({
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
  wpUploadIgnoreWarning = T.nullable(T.string({ max=512 })),
  wpUploadSource = T.nullable(T.string({ max=512 })),
  wpWatchthis = T.nullable(T.string({ max=512 })),
})

local upload_route = {
  name    = "index php special upload post",
  method  = "POST",
  path    = [[^/index\.php/Special:Upload(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = upload_form,
}

-- block (Special:Block, SpecialBlock) -- Specials/SpecialBlock.php
local block_form = T.object({
  id = T.nullable(T.string({ max=512 })),
  ip = T.nullable(T.string({ max=512 })),
  multiblocks = T.nullable(T.string({ max=512 })),
  usecodex = T.nullable(T.string({ max=512 })),
  wpAutoBlock = T.nullable(T.string({ max=512 })),
  wpBlockAddress = T.nullable(T.string({ max=512 })),
  wpCreateAccount = T.nullable(T.string({ max=512 })),
  wpDisableEmail = T.nullable(T.string({ max=512 })),
  wpDisableUTEdit = T.nullable(T.string({ max=512 })),
  wpEditingRestriction = T.nullable(T.string({ max=512 })),
  wpExpiry = T.nullable(T.string({ max=512 })),
  wpHardBlock = T.nullable(T.string({ max=512 })),
  wpHideUser = T.nullable(T.string({ max=512 })),
  wpNamespaceRestrictions = T.nullable(T.string({ max=512 })),
  wpPageRestrictions = T.nullable(T.string({ max=512 })),
  wpPreviousTarget = T.nullable(T.string({ max=512 })),
  wpReason = T.nullable(T.string({ max=1024 })),
  wpRemovalReason = T.nullable(T.string({ max=1024 })),
  wpTarget = T.nullable(T.string({ max=512 })),
  wpWatch = T.nullable(T.string({ max=512 })),
})

local block_route = {
  name    = "index php special block post",
  method  = "POST",
  path    = [[^/index\.php/Special:Block(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = block_form,
}

-- unblock (Special:Unblock, SpecialUnblock) -- Specials/SpecialUnblock.php
local unblock_form = T.object({
  ip = T.nullable(T.string({ max=512 })),
  usecodex = T.nullable(T.string({ max=512 })),
  wpBlockAddress = T.nullable(T.string({ max=512 })),
  wpTarget = T.nullable(T.string({ max=512 })),
})

local unblock_route = {
  name    = "index php special unblock post",
  method  = "POST",
  path    = [[^/index\.php/Special:Unblock(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = unblock_form,
}

-- movepage (Special:Movepage, SpecialMovePage) -- Specials/SpecialMovePage.php
local movepage_form = T.object({
  action = T.nullable(T.string({ max=512 })),
  target = T.nullable(T.string({ max=512 })),
  wpDeleteAndMove = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpFixRedirects = T.nullable(T.string({ max=512 })),
  wpLeaveRedirect = T.nullable(T.string({ max=512 })),
  wpMoveOverProtection = T.nullable(T.string({ max=512 })),
  wpMoveOverSharedFile = T.nullable(T.string({ max=512 })),
  wpMovesubpages = T.nullable(T.string({ max=512 })),
  wpMovetalk = T.nullable(T.string({ max=512 })),
  wpNewTitle = T.nullable(T.string({ max=512 })),
  wpNewTitleMain = T.nullable(T.string({ max=512 })),
  wpNewTitleNs = T.nullable(T.string({ max=512 })),
  wpOldTitle = T.nullable(T.string({ max=512 })),
  wpReason = T.nullable(T.string({ max=1024 })),
  wpReasonList = T.nullable(T.string({ max=512 })),
  wpWatch = T.nullable(T.string({ max=512 })),
  wpWatchlistExpiry = T.nullable(T.string({ max=512 })),
})

local movepage_route = {
  name    = "index php special movepage post",
  method  = "POST",
  path    = [[^/index\.php/Special:Movepage(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = movepage_form,
}

-- userrights (Special:Userrights, SpecialUserRights) -- Specials/SpecialUserRights.php
local userrights_form = T.object({
  saveusergroups = T.nullable(T.string({ max=512 })),
  user = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpWatch = T.nullable(T.string({ max=512 })),
})

local userrights_route = {
  name    = "index php special userrights post",
  method  = "POST",
  path    = [[^/index\.php/Special:Userrights(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = userrights_form,
}

-- import (Special:Import, SpecialImport) -- Specials/SpecialImport.php
local import_form = T.object({
  action = T.nullable(T.string({ max=512 })),
  assignKnownUsers = T.nullable(T.string({ max=512 })),
  frompage = T.nullable(T.string({ max=512 })),
  interwiki = T.nullable(T.string({ max=512 })),
  interwikiHistory = T.nullable(T.string({ max=512 })),
  interwikiTemplates = T.nullable(T.string({ max=512 })),
  mapping = T.nullable(T.string({ max=512 })),
  namespace = T.nullable(T.string({ max=512 })),
  rootpage = T.nullable(T.string({ max=512 })),
  source = T.nullable(T.string({ max=512 })),
  subproject = T.nullable(T.string({ max=512 })),
  usernamePrefix = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
})

local import_route = {
  name    = "index php special import post",
  method  = "POST",
  path    = [[^/index\.php/Special:Import(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = import_form,
}

-- export (Special:Export, SpecialExport) -- Specials/SpecialExport.php
local export_form = T.object({
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
  pages = T.nullable(T.string({ max=512 })),
  templates = T.nullable(T.string({ max=512 })),
  wpDownload = T.nullable(T.string({ max=512 })),
})

local export_route = {
  name    = "index php special export post",
  method  = "POST",
  path    = [[^/index\.php/Special:Export(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = export_form,
}

-- undelete (Special:Undelete, SpecialUndelete) -- Specials/SpecialUndelete.php
local undelete_form = T.object({
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
  wpCommentList = T.nullable(T.string({ max=2048 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpUnsuppress = T.nullable(T.string({ max=512 })),
  wpWatch = T.nullable(T.string({ max=512 })),
})

local undelete_route = {
  name    = "index php special undelete post",
  method  = "POST",
  path    = [[^/index\.php/Special:Undelete(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = undelete_form,
}

-- emailuser (Special:Emailuser, SpecialEmailUser) -- Specials/SpecialEmailUser.php
local emailuser_form = T.object({
  target = T.nullable(T.string({ max=512 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
  wpTarget = T.nullable(T.string({ max=512 })),
})

local emailuser_route = {
  name    = "index php special emailuser post",
  method  = "POST",
  path    = [[^/index\.php/Special:Emailuser(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = emailuser_form,
}

-- mergehistory (Special:MergeHistory, SpecialMergeHistory) -- Specials/SpecialMergeHistory.php
local mergehistory_form = T.object({
  action = T.nullable(T.string({ max=512 })),
  dest = T.nullable(T.string({ max=512 })),
  destID = T.nullable(T.string({ max=512 })),
  mergepoint = T.nullable(T.string({ max=512 })),
  mergepointold = T.nullable(T.string({ max=512 })),
  submitted = T.nullable(T.string({ max=512 })),
  target = T.nullable(T.string({ max=512 })),
  targetID = T.nullable(T.string({ max=512 })),
  wpComment = T.nullable(T.string({ max=1024 })),
  wpEditToken = T.nullable(T.string({ max=512 })),
})

local mergehistory_route = {
  name    = "index php special mergehistory post",
  method  = "POST",
  path    = [[^/index\.php/Special:MergeHistory(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = mergehistory_form,
}

-- blocklist (Special:BlockList, SpecialBlockList) -- Specials/SpecialBlockList.php
local blocklist_form = T.object({
  action = T.nullable(T.string({ max=512 })),
  blockType = T.nullable(T.string({ max=512 })),
  ip = T.nullable(T.string({ max=512 })),
  wpOptions = T.nullable(T.string({ max=512 })),
  wpTarget = T.nullable(T.string({ max=512 })),
})

local blocklist_route = {
  name    = "index php special blocklist post",
  method  = "POST",
  path    = [[^/index\.php/Special:BlockList(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = blocklist_form,
}

-- changecontentmodel (Special:ChangeContentModel, SpecialChangeContentModel) -- Specials/SpecialChangeContentModel.php
local changecontentmodel_form = T.object({
  pagetitle = T.nullable(T.string({ max=512 })),
})

local changecontentmodel_route = {
  name    = "index php special changecontentmodel post",
  method  = "POST",
  path    = [[^/index\.php/Special:ChangeContentModel(?:/.*)?$]],
  content_types = { "application/x-www-form-urlencoded", "multipart/form-data" },
  form    = changecontentmodel_form,
}

