-- ==========================================================================
-- TIER 2: write/mutation action modules
-- Paste each block's contents into mw_api_actions in mediawiki.lua
-- ==========================================================================
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

-- delete (ApiDelete) -- includes/Api/ApiDelete.php
  delete = {
    deletetalk = T.nullable(T.string({ max=8 })),
    oldimage = T.nullable(T.string({ max=512 })),
    pageid = T.nullable(T.number_query({ integer=true })),
    reason = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
    unwatch = T.nullable(T.string({ max=512 })),
    watch = T.nullable(T.string({ max=512 })),
  },

-- undelete (ApiUndelete) -- includes/Api/ApiUndelete.php
  undelete = {
    fileids = T.nullable(T.number_query({ integer=true })),
    reason = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    timestamps = T.nullable(T.string({ max=2048 })),  -- mediawiki type: timestamp
    title = T.string({ max=512 }),
    token = T.nullable(T.string({ max=512 })),
    undeletetalk = T.nullable(T.string({ max=8 })),
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
    token = T.nullable(T.string({ max=512 })),
    watch = T.nullable(T.string({ max=512 })),
  },

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
    token = T.nullable(T.string({ max=512 })),
    user = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    userid = T.nullable(T.number_query({ integer=true })),
    watchlistexpiry = T.nullable(T.string({ max=512 })),
    watchuser = T.nullable(T.string({ max=8 })),
  },

-- unblock (ApiUnblock) -- includes/Api/ApiUnblock.php
  unblock = {
    id = T.nullable(T.number_query({ integer=true })),
    reason = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    token = T.nullable(T.string({ max=512 })),
    user = T.nullable(T.string({ max=512 })),  -- mediawiki type: user
    userid = T.nullable(T.number_query({ integer=true })),
    watchlistexpiry = T.nullable(T.string({ max=512 })),
    watchuser = T.nullable(T.string({ max=8 })),
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
    token = T.nullable(T.string({ max=512 })),
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
    token = T.nullable(T.string({ max=512 })),
    url = T.nullable(T.string({ max=512 })),
    watch = T.nullable(T.string({ max=512 })),
  },

-- filerevert (ApiFileRevert) -- includes/Api/ApiFileRevert.php
  filerevert = {
    archivename = T.string({ max=512 }),
    comment = T.nullable(T.string({ max=512 })),
    filename = T.string({ max=512 }),
    token = T.nullable(T.string({ max=512 })),
  },

-- emailuser (ApiEmailUser) -- includes/Api/ApiEmailUser.php
  emailuser = {
    ccme = T.nullable(T.string({ max=8 })),
    subject = T.string({ max=512 }),
    target = T.string({ max=512 }),
    text = T.string({ max=1048576 }),
    token = T.nullable(T.string({ max=512 })),
  },

-- watch (ApiWatch) -- includes/Api/ApiWatch.php
  watch = {
    ['continue'] = T.nullable(T.string({ max=512 })),
    expiry = T.nullable(T.string({ max=512 })),
    labels = T.nullable(T.number_query({ integer=true })),
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
    unwatch = T.nullable(T.string({ max=8 })),
  },

-- patrol (ApiPatrol) -- includes/Api/ApiPatrol.php
  patrol = {
    rcid = T.nullable(T.number_query({ integer=true })),
    revid = T.nullable(T.number_query({ integer=true })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    token = T.nullable(T.string({ max=512 })),
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
    token = T.nullable(T.string({ max=512 })),
    xml = T.nullable(T.string({ max=512 })),  -- mediawiki type: upload
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

-- options (ApiOptions) -- includes/Api/ApiOptions.php
  options = {
    change = T.nullable(T.string({ max=2048 })),
    global = T.nullable(T.string({ max=8, enum={ ['ignore']=true, ['update']=true, ['override']=true, ['create']=true } })),
    optionname = T.nullable(T.string({ max=512 })),
    optionvalue = T.nullable(T.string({ max=512 })),
    reset = T.nullable(T.string({ max=8 })),
    resetkinds = T.nullable(T.string({ max=2048 })),  -- dynamic enum from '$optionKinds', left generic
    token = T.nullable(T.string({ max=512 })),
  },

-- imagerotate (ApiImageRotate) -- includes/Api/ApiImageRotate.php
  imagerotate = {
    ['continue'] = T.nullable(T.string({ max=512 })),
    rotation = T.string({ max=3, enum={ ['90']=true, ['180']=true, ['270']=true } }),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    token = T.nullable(T.string({ max=512 })),
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
    token = T.nullable(T.string({ max=512 })),
    ['type'] = T.string({ max=512 }),  -- dynamic enum from 'RevisionDeleter::getTypes()', left generic
  },

-- managetags (ApiManageTags) -- includes/Api/ApiManageTags.php
  managetags = {
    ignorewarnings = T.nullable(T.string({ max=8 })),
    operation = T.string({ max=10, enum={ ['create']=true, ['delete']=true, ['activate']=true, ['deactivate']=true } }),
    reason = T.nullable(T.string({ max=512 })),
    tag = T.string({ max=512 }),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    token = T.nullable(T.string({ max=512 })),
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
    token = T.nullable(T.string({ max=512 })),
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
    token = T.nullable(T.string({ max=512 })),
  },

-- setpagelanguage (ApiSetPageLanguage) -- includes/Api/ApiSetPageLanguage.php
  setpagelanguage = {
    lang = T.string({ max=7, enum={ ['default']=true } }),
    pageid = T.nullable(T.number_query({ integer=true })),
    reason = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
  },

-- changecontentmodel (ApiChangeContentModel) -- includes/Api/ApiChangeContentModel.php
  changecontentmodel = {
    bot = T.nullable(T.string({ max=8 })),
    model = T.string({ max=512 }),  -- dynamic enum from '$modelOptions', left generic
    pageid = T.nullable(T.number_query({ integer=true })),
    summary = T.nullable(T.string({ max=512 })),
    tags = T.nullable(T.string({ max=2048 })),  -- mediawiki type: tags
    title = T.nullable(T.string({ max=512 })),
    token = T.nullable(T.string({ max=512 })),
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
    token = T.nullable(T.string({ max=512 })),
  },

-- ==========================================================================
-- TIER 5: remaining read/utility action modules
-- ==========================================================================
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

-- help (ApiHelp) -- includes/Api/ApiHelp.php
  help = {
    modules = T.nullable(T.string({ max=2048 })),
    recursivesubmodules = T.nullable(T.string({ max=8 })),
    submodules = T.nullable(T.string({ max=8 })),
    toc = T.nullable(T.string({ max=8 })),
    wrap = T.nullable(T.string({ max=8 })),
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

-- rsd (ApiRsd) -- includes/Api/ApiRsd.php
  rsd = {
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

-- purge (ApiPurge) -- includes/Api/ApiPurge.php
  purge = {
    ['continue'] = T.nullable(T.string({ max=512 })),
    forcelinkupdate = T.nullable(T.string({ max=8 })),
    forcerecursivelinkupdate = T.nullable(T.string({ max=8 })),
  },

-- setnotificationtimestamp (ApiSetNotificationTimestamp) -- includes/Api/ApiSetNotificationTimestamp.php
  setnotificationtimestamp = {
    ['continue'] = T.nullable(T.string({ max=512 })),
    entirewatchlist = T.nullable(T.string({ max=8 })),
    newerthanrevid = T.nullable(T.number_query({ integer=true })),
    timestamp = T.nullable(T.string({ max=512 })),  -- mediawiki type: timestamp
    token = T.nullable(T.string({ max=512 })),
    torevid = T.nullable(T.number_query({ integer=true })),
  },

-- languagesearch (ApiLanguageSearch) -- includes/Api/ApiLanguageSearch.php
  languagesearch = {
    search = T.string({ max=512 }),
    typos = T.nullable(T.number_query({ integer=true })),
  },

-- ==========================================================================
-- TIER 3 + 4: action=query submodules (prop=/list=/meta=)
-- These are looked up by NAME from prop=/list=/meta= (pipe-separated), not
-- from `action` directly - paste into mw_query_submodules, keyed by kind.
-- ==========================================================================
-- ---- meta submodules (7) ----
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

-- ---- prop submodules (20) ----
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

-- ---- list submodules (37) ----
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

