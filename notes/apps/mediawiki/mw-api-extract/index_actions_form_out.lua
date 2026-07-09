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
