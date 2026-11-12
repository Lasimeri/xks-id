#!/bin/sh
# wire.sh: connects "xksid hook" to a harness, so the model is told about the flagged turns of its
# own session. It changes one file of the harness and says which. Running it again changes nothing.
#
#   wire.sh claude-code [SETTINGS]   adds the entries of claude-code/hooks.json to the hooks of
#                                    SETTINGS (default ~/.claude/settings.json), next to the hooks
#                                    already there. The file as it was is kept beside it. Needs jq.
#   wire.sh omp [PROFILE]            installs omp/xks-id.ts and links it into the hook directory of
#                                    the profile: ~/.omp/agent/hooks/pre for the default profile,
#                                    ~/.omp/profiles/PROFILE/agent/hooks/pre for a named one.
#
# XKS-Memory must be attached to the same harness (and, for omp, to the same profile): xksid reads
# what XKS-Memory records, so a harness that is not recorded has nothing to be told.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
die() { echo "wire.sh: $1" >&2; exit 1; }

wire_claude_code() {
    settings=${1:-$HOME/.claude/settings.json}
    entries=$HERE/claude-code/hooks.json
    command -v jq >/dev/null 2>&1 || die "jq is not installed: merge $entries into $settings by hand"
    [ -f "$settings" ] || die "$settings does not exist: start Claude Code once, or create it with {} in it"
    jq -e 'type == "object"' "$settings" >/dev/null 2>&1 || die "$settings is not a JSON object: nothing was changed"
    # an event that already runs "xksid hook" is left alone, so a second run adds nothing
    merged=$(jq --slurpfile add "$entries" '
        .hooks = reduce ($add[0].hooks | to_entries[]) as $e (.hooks // {};
            if any((.[$e.key] // [])[]; any(.hooks[]?; (.command // "") | test("xksid hook")))
            then . else .[$e.key] = ((.[$e.key] // []) + $e.value) end)' "$settings")
    if [ "$merged" = "$(jq . "$settings")" ]; then
        echo "claude-code: $settings already runs xksid hook, nothing changed"
        return
    fi
    kept=$settings.before-xksid-$(date +%Y%m%d-%H%M%S)
    cp -p "$settings" "$kept"
    cp -p "$settings" "$settings.xksid-tmp"            # the new file keeps the mode of the old one
    printf '%s\n' "$merged" > "$settings.xksid-tmp"
    mv "$settings.xksid-tmp" "$settings"
    echo "claude-code: xksid hook added to PostToolUse, UserPromptSubmit and Stop in $settings"
    echo "claude-code: the file as it was: $kept"
    echo "claude-code: sessions that are already running may need /hooks opened once, or a restart"
}

wire_omp() {
    profile=${1:-}
    if [ -n "$profile" ]; then agent=$HOME/.omp/profiles/$profile/agent; else agent=$HOME/.omp/agent; fi
    [ -d "$agent" ] || die "$agent does not exist: no such omp profile"
    data=${XDG_DATA_HOME:-$HOME/.local/share}/xksid/omp
    link=$agent/hooks/pre/xks-id.ts
    if [ -e "$link" ] && [ ! -L "$link" ]; then die "$link is a file of its own, not a link: nothing was changed"; fi
    install -d "$data" "$agent/hooks/pre"
    install -m 644 "$HERE/omp/xks-id.ts" "$data/xks-id.ts"
    ln -sfn "$data/xks-id.ts" "$link"
    echo "omp: $link -> $data/xks-id.ts"
    [ -e "$agent/hooks/pre/xks-memory.ts" ] \
        || echo "omp: note: XKS-Memory is not attached to this profile, so its turns are not recorded and nothing will be flagged"
    echo "omp: the notice arrives at the next prompt of a session started from now on"
}

case "${1-}" in
    claude-code) wire_claude_code "${2-}" ;;
    omp)         wire_omp "${2-}" ;;
    *)           sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
