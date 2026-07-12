#!/usr/bin/env python3
"""
Generates rootfs/etc/openresty/waf/apps/mediawiki/edit_forms.lua: the
standard wikitext edit-submission form (EditPage.php, from
editpage-fields.json) plus one form per index.php action=X POST target
(delete, protect, purge, revert, rollback, watch/unwatch, markpatrolled,
mcrundo, mcrrestore, ... from index-actions.json).

Replaces gen_editpage_form.py + gen_index_actions_form.py + their two
integrate_*.py splicers. Writes one complete, standalone Lua module
(wholesale overwrite, no markers) instead of splicing generated fragments
into mediawiki.lua - mediawiki.lua's "index php post" route just
`require`s this file and references edit_forms.index_post_form /
edit_forms.action_forms directly.

Field names in both cases are candidate names only (heuristic
$request->getXxx() scan / getFormFields() where available, not full type
info), so most fields are modeled as generously-capped nullable strings.

Usage: python3 gen_edit_forms.py
"""
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from _lib import find_repo_root, lua_str, field_key  # noqa: E402

ROOT = find_repo_root(SCRIPT_DIR)
OUT_PATH = os.path.join(ROOT, "rootfs/etc/openresty/waf/apps/mediawiki/edit_forms.lua")

DEFAULT_MAX = 512

# index_post_form's field-specific tuning (EditPage.php's wikitext edit form).
EDITPAGE_LONG_FIELD_HINTS = {
    "textbox": 1024 * 1024,   # wpTextbox1/wpTextbox2 - full page content
    "summary": 2048,
    "changetags": 2048,
    "preloadparams": 2048,
    "watchlistlabels": 2048,  # MenuTagMultiselectWidget - can hold several selections
}

# Presence-based checkboxes (any submitted value means "checked") - same
# convention as the MediaWiki API's boolean params. wpSave is NOT one of
# these despite looking like a submit flag: classic
# <input type=submit name=wpSave value="Save changes"> buttons submit their
# translated DISPLAY LABEL as the value ("Save changes" = 13 chars, other
# languages/skins can run longer), not a short fixed token - capping it at
# 8 like a real boolean flag false-positived on every real save (confirmed
# live: max=8 rejected the literal string "Save changes").
EDITPAGE_BOOLEAN_FIELDS = {
    "bot", "minor", "nosummary", "preview", "redlink", "watchthis",
    "wpMinoredit", "wpPreview", "wpWatchthis", "wpIgnoreBlankArticle",
    "wpIgnoreBlankSummary", "wpIgnoreProblematicRedirects",
    "wpIgnoreRevisionDeleted", "wpRecreate", "wpAllowedProblematicRedirectTarget",
    "wpChangeTagsAfterPreview",
}

# Fields with a known fixed/enum shape that the generic string treatment
# would blur.
EDITPAGE_FIELD_OVERRIDES = {
    "wpUltimateParam": "T.nullable(T.string({ max=4, enum={ ['1']=true } }))",
    "wpUnicodeCheck": "T.nullable(T.string({ max=64 }))",  # fixed UTF-8 sanity-check string
    "wpAntispam": "T.nullable(T.string({ max=64 }))",  # honeypot; MediaWiki rejects non-empty values
}

# index.php action=X forms' field-specific tuning.
ACTIONS_LONG_FIELD_HINTS = {
    "reason": 1024,
    "comment": 1024,
    "summary": 2048,
}
ACTIONS_BOOLEAN_FIELDS = {"wpDeleteTalk", "wpSuppress", "wpWatch"}


def _tokenize(name):
    # Splits on camelCase boundaries and non-alnum separators, e.g.
    # "wpContextTitle" -> {"wp", "context", "title"}. Whole-word hint
    # matching against these tokens (instead of raw substring containment
    # against the full lowercased name) avoids accidental collisions like
    # "wpContextTitle" matching a "text" hint purely because
    # "con-TEXT-title" contains those 4 letters in a row - the same class of
    # bug confirmed live in gen_all_special_pages.py's identical cap_for(),
    # fixed there first; applied here too since this file has the same
    # substring-matching shape.
    import re
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return set(re.split(r"[^A-Za-z0-9]+", spaced.lower())) - {""}


def _cap_for(name, hints):
    tokens = _tokenize(name)
    for hint, cap in hints.items():
        if hint in tokens:
            return cap
    return DEFAULT_MAX


def _editpage_field_lua(name, indent):
    if name in EDITPAGE_FIELD_OVERRIDES:
        inner = EDITPAGE_FIELD_OVERRIDES[name]
    elif name in EDITPAGE_BOOLEAN_FIELDS:
        inner = "T.nullable(T.string({ max=8 }))"
    else:
        inner = f"T.nullable(T.string({{ max={_cap_for(name, EDITPAGE_LONG_FIELD_HINTS)} }}))"
    return f"{indent}{field_key(name)} = {inner},"


def _action_field_lua(name, indent):
    if name in ACTIONS_BOOLEAN_FIELDS:
        inner = "T.nullable(T.string({ max=8 }))"
    else:
        inner = f"T.nullable(T.string({{ max={_cap_for(name, ACTIONS_LONG_FIELD_HINTS)} }}))"
    return f"{indent}{field_key(name)} = {inner},"


def _label_for(cls):
    import re
    return re.sub(r"[^a-z0-9]", "", cls.lower())


def main():
    with open(os.path.join(SCRIPT_DIR, "editpage-fields.json")) as f:
        editpage_entry = json.load(f)
    editpage_fields = sorted(editpage_entry.get("fields") or {})

    with open(os.path.join(SCRIPT_DIR, "index-actions.json")) as f:
        actions_data = json.load(f)

    out = []
    out.append("-- Generated by gen_edit_forms.py - do not hand-edit, re-run the generator.")
    out.append("local T = require \"waf.types\"")
    out.append("--")
    out.append("-- index_post_form: the standard wikitext edit-submission form (EditPage.php),")
    out.append("-- from editpage-fields.json (extract_mediawiki_api.py, heuristic")
    out.append("-- $request->getXxx() scan - candidate field NAMES only, no type info, so most")
    out.append("-- fields are generously-capped nullable strings; a handful of known")
    out.append("-- checkbox/enum fields get a tighter override above). None are marked required")
    out.append("-- since MediaWiki's own form-building logic determines which fields are")
    out.append("-- present per action (preview/save/diff).")
    out.append("local index_post_form = T.object({")
    for name in editpage_fields:
        out.append(_editpage_field_lua(name, "  "))
    out.append("})")
    out.append("")
    out.append("-- action_forms: one per index.php action=X POST target")
    out.append("-- (includes/Actions/*.php + Page/ProtectionForm.php), from index-actions.json.")
    out.append("-- Candidate field NAMES only (getFormFields() types where available, else a")
    out.append("-- heuristic scan). title/wpEditToken/wpFormIdentifier are added to every form:")
    out.append("-- they're injected unconditionally by HTMLForm::getHiddenFields() for any")
    out.append("-- POST-method form, not read back by the action's own code, so no scan of it")
    out.append("-- ever finds them. Which action= a POST is for lives in the query string, not")
    out.append("-- the body, so mediawiki.lua's \"index php post\" route tries index_post_form")
    out.append("-- and every one of these in turn via form_schemas (core.lua: passes if any")
    out.append("-- one matches).")
    action_labels = []
    for cls in sorted(actions_data.keys()):
        entry = actions_data[cls]
        label = _label_for(cls)
        action_labels.append(label)
        fields = dict(entry.get("fields") or {})
        fields.setdefault("title", {"type": "string"})
        fields.setdefault("wpEditToken", {"type": "string"})
        fields.setdefault("wpFormIdentifier", {"type": "string"})

        out.append(f"-- {cls} (action={entry.get('action')!r}, method={entry.get('method')}) -- {entry.get('file')}")
        out.append(f"local action_{label}_form = T.object({{")
        for name in sorted(fields):
            out.append(_action_field_lua(name, "  "))
        out.append("})")
        out.append("")

    out.append("return {")
    out.append("  index_post_form = index_post_form,")
    out.append("  action_forms = {")
    for label in action_labels:
        out.append(f"    action_{label}_form,")
    out.append("  },")
    out.append("}")

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    print(f"Wrote {OUT_PATH} ({len(editpage_fields)} index_post_form fields, "
          f"{len(action_labels)} action forms)")


if __name__ == "__main__":
    main()
