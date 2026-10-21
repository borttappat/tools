#!@bash@
# cashe-demo: try cashe in a clean shell without installing anything.
#
# Starts bash, zsh or fish (default: your $SHELL if it is one of those, else
# bash) recorded by cashe, with only cashe's snippet loaded (no rc files of
# your own) and recordings in a temporary directory, so nothing in your home
# changes. Exiting the shell ends the demo and lists what was recorded.
set -euo pipefail

cashe="@cashe@"
share="@share@"

shell=${1:-$(basename -- "${SHELL:-bash}")}
case $shell in
  bash | zsh | fish) ;;
  -h | --help)
    echo "Usage: cashe-demo [bash|zsh|fish]"
    exit 0
    ;;
  *) shell=bash ;;
esac

demo=$(mktemp -d "${TMPDIR:-/tmp}/cashe-demo.XXXXXX")
export CASHE_DIR="$demo/logs"
export PATH="${cashe%/*}:$PATH"

# Each shell starts with the cashe snippet as its only configuration.
case $shell in
  bash)
    printf 'PS1="[cashe-demo] \\w \\$ "\nsource %q\n' "$share/init.sh" >"$demo/bashrc"
    CASHE_SHELL="$(printf '%q --noprofile --rcfile %q' "@bashInteractive@" "$demo/bashrc")"
    ;;
  zsh)
    mkdir -p "$demo/zdot"
    printf 'PS1="[cashe-demo] %%~ %%# "\nsource %q\n' "$share/init.sh" >"$demo/zdot/.zshrc"
    export ZDOTDIR="$demo/zdot"
    CASHE_SHELL="$(printf '%q' "@zsh@")"
    ;;
  fish)
    CASHE_SHELL="$(printf '%q --no-config -C %q' "@fish@" "source $share/init.fish")"
    ;;
esac
export CASHE_SHELL

cat <<EOF

  cashe demo: recorded $shell, recordings in $CASHE_DIR

  echo hello            run anything, it is recorded
  rec                   this session's name and path
  rec -r my-session     rename this session
  rec -l                list sessions (* = this terminal)
  rec -p [SESSION]      print a session as text (default: this one)
  rec -a                print every session as text
  rec -x                stop recording, keep the terminal open
  rec -s                start a fresh recording
  cashe --help          all commands (rec is short for cashe)
  exit                  leave the demo

EOF

"$cashe" session || true

echo
echo "cashe demo finished. Recordings:"
"$cashe" -l
echo
echo "Read one with:  CASHE_DIR=$CASHE_DIR $cashe -p <name>"
echo "Delete them:    rm -r $demo"
