# cashe for bash and zsh: record every interactive terminal.
# Load with: eval "$(cashe init bash)"  (or zsh), early in ~/.bashrc / ~/.zshrc.

case $- in
  *i*)
    if [ -t 1 ] && [ -z "${CASHE:-}" ] && [ -z "${CASHE_DISABLE:-}" ] &&
      [ "${TERM:-dumb}" != dumb ] && [ "${TERM:-}" != linux ]; then
      if [ -n "${BASH_VERSION:-}" ]; then
        export CASHE_SHELL="${CASHE_SHELL:-${BASH:-bash}}"
      else
        export CASHE_SHELL="${CASHE_SHELL:-$(readlink /proc/$$/exe 2>/dev/null || echo zsh)}"
      fi
      exec @cashe@ session
    fi
    ;;
esac

# rec: cashe, plus -x/-s, which have to run in this shell to end or replace it.
function rec {
  case "${1:-}" in
    -x | stop) stop-recording ;;
    -s | start) start-recording ;;
    *) @cashe@ "$@" ;;
  esac
}

# Toggle the recorder without closing the terminal: stop ends the current
# recording and drops to a plain shell; start begins a fresh recording.
function stop-recording {
  if [ -z "${CASHE_STOP:-}" ]; then
    echo "Not recording."
    return 1
  fi
  : >"$CASHE_STOP"
  exit
}
function start-recording {
  if [ -n "${CASHE_STOP:-}" ]; then
    echo "Already recording: $(@cashe@ -c)"
    return 1
  fi
  unset CASHE
  exec @cashe@ session
}

# `cat`-ing the live recording would feed its own output back into the growing
# file and loop; show a clean text render instead. Every other `cat` passes
# straight through.
if [ -n "${CASHE_STATE:-}" ]; then
  function cat {
    if [ $# -eq 1 ] && [ -f "$CASHE_STATE" ] &&
      [ "$(command realpath -- "$1" 2>/dev/null)" = "$(command head -n1 -- "$CASHE_STATE")" ]; then
      @cashe@ -p
    else
      command cat "$@"
    fi
  }
fi
