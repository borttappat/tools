#!@bash@
# cashe: record every interactive terminal with asciinema, name the sessions,
# and read them back as plain text.
#
# A shell's init snippet (`cashe init bash|zsh|fish`) execs `cashe session`
# when an interactive terminal opens. That runs asciinema around a fresh copy of
# the shell, which sees $CASHE and does not record again. On exit the .cast is
# rendered to a plain-text twin (.txt) with `asciinema convert`, which emulates a
# terminal, so prompt and line-editing redraws come out as a readable transcript.
#
# The current session's path lives in a state file ($CASHE_STATE), not in the
# shell's environment, so `cashe -r` can rename a live recording (asciinema
# keeps writing through its open descriptor) and every later lookup, including
# the final conversion, follows the new name.
set -euo pipefail

# Tools come from the package, but the recorded shell gets the caller's PATH back.
orig_path=$PATH
export PATH="@path@:$PATH"
share="@share@"
dir=${CASHE_DIR:-$HOME/terminal_logs}

die() {
  echo "cashe: $*" >&2
  exit 1
}

stem() {
  local b
  b=$(basename -- "$1")
  printf '%s\n' "${b%.*}"
}

current() {
  [ -n "${CASHE_STATE:-}" ] && [ -s "$CASHE_STATE" ] && head -n1 -- "$CASHE_STATE"
}

# Sessions oldest first, one path per line.
sessions() {
  local files=()
  shopt -s nullglob
  files=("$dir"/*.cast)
  shopt -u nullglob
  [ ${#files[@]} -gt 0 ] || return 0
  ls -tr -- "${files[@]}"
}

# A cast as clean text. The input is snapshotted first so a still-growing live
# recording can't change under the converter, and asciinema convert only
# writes txt to a real file, so it goes via a temp file.
render() {
  local in out
  in=$(mktemp)
  out=$(mktemp)
  head -c "$(stat -c %s -- "$1")" -- "$1" >"$in"
  asciinema convert --overwrite -f txt "$in" "$out" 2>/dev/null || true
  cat -- "$out"
  rm -f -- "$in" "$out"
}

# A finished session prints its .txt twin; a live one is rendered on the fly.
show() {
  local txt=${1%.cast}.txt
  if [ "$1" != "$(current || true)" ] && [ -f "$txt" ]; then
    cat -- "$txt"
  else
    render "$1"
  fi
}

# A session by name, unique part of a name, or path.
find_session() {
  local arg=$1 base hits=()
  if [ -f "$arg" ]; then
    realpath -- "$arg"
    return
  fi
  base=$(basename -- "$arg")
  base=${base%.cast}
  base=${base%.txt}
  if [ -f "$dir/$base.cast" ]; then
    printf '%s\n' "$dir/$base.cast"
    return
  fi
  shopt -s nullglob
  hits=("$dir"/*"$base"*.cast)
  shopt -u nullglob
  case ${#hits[@]} in
    1) printf '%s\n' "${hits[0]}" ;;
    0) die "no session matching '$arg'" ;;
    *)
      echo "cashe: '$arg' matches several sessions:" >&2
      for f in "${hits[@]}"; do echo "  $(stem "$f")" >&2; done
      exit 1
      ;;
  esac
}

cmd_session() {
  CASHE_SHELL=${CASHE_SHELL:-${SHELL:-sh}}
  mkdir -p -- "$dir"
  local id run rc=0 cast asciinema
  id=$(date +%Y%m%d-%H%M%S)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')
  run=${XDG_RUNTIME_DIR:-/tmp}
  export CASHE=1 CASHE_SHELL CASHE_DIR=$dir
  export CASHE_FILE="$dir/$id.cast"
  export CASHE_STATE="$run/cashe-$id" CASHE_STOP="$run/cashe-$id.stop"
  printf '%s\n' "$CASHE_FILE" >"$CASHE_STATE"
  asciinema=$(command -v asciinema)
  PATH=$orig_path "$asciinema" rec --quiet -c "$CASHE_SHELL" "$CASHE_FILE" || rc=$?
  cast=$(current)
  rm -f -- "$CASHE_STATE"
  "$asciinema" convert --overwrite -f txt "$cast" "${cast%.cast}.txt" 2>/dev/null || true
  # stop-recording left a sentinel: continue in a plain, unrecorded shell
  # rather than closing the terminal. CASHE stays set so it doesn't record.
  if [ -e "$CASHE_STOP" ]; then
    rm -f -- "$CASHE_STOP"
    unset CASHE_FILE CASHE_STATE CASHE_STOP
    PATH=$orig_path exec sh -c "exec $CASHE_SHELL"
  fi
  exit "$rc"
}

cmd_current() {
  local f
  f=$(current) || {
    echo "Not recording."
    return 1
  }
  printf '%s  %s\n' "$(stem "$f")" "$f"
}

cmd_list() {
  local f mark cur
  cur=$(current || true)
  [ -n "$(sessions)" ] || {
    echo "No recordings in $dir"
    return 0
  }
  while IFS= read -r f; do
    mark=" "
    [ "$f" = "$cur" ] && mark="*"
    printf '%s %-32s %s  %5s\n' "$mark" "$(stem "$f")" \
      "$(date -r "$f" '+%Y-%m-%d %H:%M')" "$(numfmt --to=iec "$(stat -c %s -- "$f")")"
  done < <(sessions)
}

cmd_rename() {
  local cur name new
  cur=$(current) || die "not recording"
  name=${1:-}
  name=${name%.cast}
  [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "usage: cashe -r NAME  (letters, digits, . _ -)"
  new="$(dirname -- "$cur")/$name.cast"
  [ "$new" = "$cur" ] && return 0
  [ -e "$new" ] || [ -e "${new%.cast}.txt" ] && die "'$name' already exists"
  mv -n -- "$cur" "$new"
  [ -e "$cur" ] && die "could not rename $cur"
  printf '%s\n' "$new" >"$CASHE_STATE"
  echo "Recording renamed: $name"
}

cmd_print() {
  local f label body
  if [ $# -gt 0 ]; then
    f=$(find_session "$1")
  else
    f=$(current) || die "not recording; name a session (cashe -l)"
  fi
  # On a terminal, frame the transcript so it can't be mistaken for live prompts.
  # The text is taken before the header is printed, or a live session's render
  # would end with its own header.
  if [ -t 1 ]; then
    label=$(stem "$f")
    [ "$f" = "$(current || true)" ] && label="$label (recording)"
    body=$(show "$f")
    printf '==> %s <==\n%s\n==> end of %s <==\n' "$label" "$body" "$(stem "$f")"
  else
    show "$f"
  fi
}

cmd_all() {
  local f
  while IFS= read -r f; do
    printf '\n==> %s <==\n' "$(stem "$f")"
    show "$f"
  done < <(sessions)
}

cmd_init() {
  case ${1:-} in
    bash | zsh) cat -- "$share/init.sh" ;;
    fish) cat -- "$share/init.fish" ;;
    *) die "usage: cashe init bash|zsh|fish" ;;
  esac
}

usage() {
  cat <<EOF
Usage: cashe [-c | -l | -r NAME | -p [SESSION] | -a]
       cashe init bash|zsh|fish
       cashe session

  -c            show the current session (default)
  -l            list sessions, oldest first (* = this terminal)
  -r NAME       rename the current session
  -p [SESSION]  print one session as text (default: current)
  -a            print every session as text
  -x            stop recording, keep the terminal open (recorded shells)
  -s            start a fresh recording (recorded shells)
  init SHELL    print the snippet that records every interactive terminal
  session       record a session of \$CASHE_SHELL (run by the snippet)

SESSION is a name, a unique part of one, or a path.
Recordings go to \$CASHE_DIR (now: $dir).
In a shell set up with \`cashe init\`, \`rec\` is short for cashe;
-x and -s (also stop-recording / start-recording) only work there.
EOF
}

case ${1:-} in
  "" | -c | current) cmd_current ;;
  -l | list) cmd_list ;;
  -r | rename) cmd_rename "${2:-}" ;;
  -p | print) shift; cmd_print "$@" ;;
  -a | all) cmd_all ;;
  -x | stop | -s | start) die "${1} needs the shell snippet: run it as 'rec ${1}' in a recorded shell" ;;
  init) cmd_init "${2:-}" ;;
  session) cmd_session ;;
  -h | --help | help) usage ;;
  *)
    usage >&2
    exit 1
    ;;
esac
