#!@bash@
# End-to-end test: drives real interactive bash, zsh and fish sessions through a
# pty (util-linux script), the way a terminal would, and checks the recordings.
#
# Usage: run.sh [bash|zsh|fish ...]   (default: all three)
set -euo pipefail

export PATH="@path@:$PATH"
termrec="@termrec@"
share="@share@"
work=$(mktemp -d "${TMPDIR:-/tmp}/termrec-test.XXXXXX")
fails=0

# Types each line into the session like a user would. "@wait" pauses long
# enough for a newly started asciinema to finish probing the terminal, which
# swallows anything typed meanwhile. The pty has no terminal emulator behind it,
# so fish is told not to wait for answers to its terminal queries.
feed() {
  sleep 3
  for l in "$@"; do
    if [ "$l" = "@wait" ]; then sleep 3; else printf '%s\n' "$l"; sleep 0.6; fi
  done
  sleep 1
}

check() {
  if eval "$2"; then
    echo "  ok    $1"
  else
    echo "  FAIL  $1"
    fails=$((fails + 1))
  fi
}

# The arithmetic is typed into the session, so it must not expand here.
# shellcheck disable=SC2016
run_shell() {
  local sh=$1 dir="$work/$1" calc cmd
  mkdir -p "$dir/rt" "$dir/home"
  case $sh in
    bash)
      printf 'PS1="$ "\nsource %q\n' "$share/init.sh" >"$dir/rc"
      cmd="$(printf '%q --noprofile --rcfile %q' "@bashInteractive@" "$dir/rc")"
      calc='$((40+2))'
      ;;
    zsh)
      mkdir -p "$dir/zdot"
      printf 'PS1="$ "\nsource %q\n' "$share/init.sh" >"$dir/zdot/.zshrc"
      cmd="$(printf '%q' "@zsh@")"
      calc='$((40+2))'
      ;;
    fish)
      cmd="$(printf '%q --no-config -C %q' "@fish@" "source $share/init.fish")"
      calc='(math 40+2)'
      ;;
  esac

  echo "== $sh"
  cd "$dir"
  feed "echo hello-$calc" "rec -r t-$sh" "echo after-rename" "cat $dir/logs/t-$sh.cast" \
    "rec -p" "rec -x" "echo unrecorded-$calc" "rec" "rec -s" "@wait" \
    "echo second-$calc" "exit" |
    env -i HOME="$dir/home" PATH="$PATH" TERM=xterm-256color XDG_RUNTIME_DIR="$dir/rt" \
      TERMREC_DIR="$dir/logs" TERMREC_SHELL="$cmd" ZDOTDIR="$dir/zdot" \
      fish_features=no-query-term \
      timeout 60 script -qfec "stty cols 100 rows 30; $termrec session" /dev/null >"$dir/screen.log" 2>&1 || true

  local t="$dir/logs/t-$sh.txt"
  export TERMREC_DIR="$dir/logs"
  check "renamed recording and its text twin exist" "[ -f '$dir/logs/t-$sh.cast' ] && [ -f '$t' ]"
  check "transcript has output from before the rename" "grep -q '^hello-42' '$t'"
  check "transcript has output from after the rename" "grep -q '^after-rename' '$t'"
  check "cat of the live cast printed text, not JSON" "! grep -q '\"version\"' '$t'"
  check "rec -p printed the live session, framed" \
    "grep -q '^==> t-$sh (recording) <==' '$t' && grep -q '^==> end of t-$sh <==' '$t'"
  check "a live render does not end with its own header" \
    "! awk '/^==> end of /{if(p ~ /^==> .* <==\$/)f=1} {p=\$0} END{exit !f}' '$t'"
  check "nothing after rec -x was recorded" "! grep -q '^unrecorded-2' '$t'"
  check "rec -s began a second session" \
    "grep -lq '^second-42' $dir/logs/*.txt && [ \$(ls $dir/logs/*.cast | wc -l) -eq 2 ]"
  check "session state files are cleaned up" "[ -z \"\$(ls -A '$dir/rt')\" ]"
  check "rec -l lists the session" "'$termrec' -l | grep 't-$sh' >/dev/null"
  check "rec -p prints the session" "'$termrec' -p t-$sh | grep '^after-rename' >/dev/null"
  check "rec -a prints every session" "[ \$('$termrec' -a | grep -cE '^==> [A-Za-z0-9._-]+ <==\$') -eq 2 ]"
}

for sh in "${@:-bash zsh fish}"; do
  for s in $sh; do run_shell "$s"; done
done

if [ "$fails" -gt 0 ]; then
  echo "$fails check(s) failed; screens and recordings kept in $work"
  exit 1
fi
rm -rf "$work"
echo "all checks passed"
