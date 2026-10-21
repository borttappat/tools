#!@bash@
# termrec-demo: try termrec in a clean shell without installing anything.
#
# Starts bash, zsh or fish (default: your $SHELL if it is one of those, else
# bash) recorded by termrec, with only termrec's snippet loaded (no rc files of
# your own) and recordings in a temporary directory, so nothing in your home
# changes. Exiting the shell ends the demo and lists what was recorded.
set -euo pipefail

termrec="@termrec@"
share="@share@"

shell=${1:-$(basename -- "${SHELL:-bash}")}
case $shell in
  bash | zsh | fish) ;;
  -h | --help)
    echo "Usage: termrec-demo [bash|zsh|fish]"
    exit 0
    ;;
  *) shell=bash ;;
esac

demo=$(mktemp -d "${TMPDIR:-/tmp}/termrec-demo.XXXXXX")
export TERMREC_DIR="$demo/logs"
export PATH="${termrec%/*}:$PATH"

# Each shell starts with the termrec snippet as its only configuration.
case $shell in
  bash)
    printf 'PS1="[termrec-demo] \\w \\$ "\nsource %q\n' "$share/init.sh" >"$demo/bashrc"
    TERMREC_SHELL="$(printf '%q --noprofile --rcfile %q' "@bashInteractive@" "$demo/bashrc")"
    ;;
  zsh)
    mkdir -p "$demo/zdot"
    printf 'PS1="[termrec-demo] %%~ %%# "\nsource %q\n' "$share/init.sh" >"$demo/zdot/.zshrc"
    export ZDOTDIR="$demo/zdot"
    TERMREC_SHELL="$(printf '%q' "@zsh@")"
    ;;
  fish)
    TERMREC_SHELL="$(printf '%q --no-config -C %q' "@fish@" "source $share/init.fish")"
    ;;
esac
export TERMREC_SHELL

cat <<EOF

  termrec demo: recorded $shell, recordings in $TERMREC_DIR

  echo hello            run anything, it is recorded
  rec                   this session's name and path
  rec -r my-session     rename this session
  rec -l                list sessions (* = this terminal)
  rec -p [SESSION]      print a session as text (default: this one)
  rec -a                print every session as text
  rec -x                stop recording, keep the terminal open
  rec -s                start a fresh recording
  termrec --help        all commands (rec is short for termrec)
  exit                  leave the demo

EOF

"$termrec" session || true

echo
echo "termrec demo finished. Recordings:"
"$termrec" -l
echo
echo "Read one with:  TERMREC_DIR=$TERMREC_DIR $termrec -p <name>"
echo "Delete them:    rm -r $demo"
