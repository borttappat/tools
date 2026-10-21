# termrec for bash and zsh: record every interactive terminal.
# Load with: eval "$(termrec init bash)"  (or zsh), early in ~/.bashrc / ~/.zshrc.

case $- in
  *i*)
    if [ -t 1 ] && [ -z "${TERMREC:-}" ] && [ -z "${TERMREC_DISABLE:-}" ] &&
      [ "${TERM:-dumb}" != dumb ] && [ "${TERM:-}" != linux ]; then
      if [ -n "${BASH_VERSION:-}" ]; then
        export TERMREC_SHELL="${TERMREC_SHELL:-${BASH:-bash}}"
      else
        export TERMREC_SHELL="${TERMREC_SHELL:-$(readlink /proc/$$/exe 2>/dev/null || echo zsh)}"
      fi
      exec @termrec@ session
    fi
    ;;
esac

# rec: termrec, plus -x/-s, which have to run in this shell to end or replace it.
function rec {
  case "${1:-}" in
    -x | stop) stop-recording ;;
    -s | start) start-recording ;;
    *) @termrec@ "$@" ;;
  esac
}

# Toggle the recorder without closing the terminal: stop ends the current
# recording and drops to a plain shell; start begins a fresh recording.
function stop-recording {
  if [ -z "${TERMREC_STOP:-}" ]; then
    echo "Not recording."
    return 1
  fi
  : >"$TERMREC_STOP"
  exit
}
function start-recording {
  if [ -n "${TERMREC_STOP:-}" ]; then
    echo "Already recording: $(@termrec@ -c)"
    return 1
  fi
  unset TERMREC
  exec @termrec@ session
}

# `cat`-ing the live recording would feed its own output back into the growing
# file and loop; show a clean text render instead. Every other `cat` passes
# straight through.
if [ -n "${TERMREC_STATE:-}" ]; then
  function cat {
    if [ $# -eq 1 ] && [ -f "$TERMREC_STATE" ] &&
      [ "$(command realpath -- "$1" 2>/dev/null)" = "$(command head -n1 -- "$TERMREC_STATE")" ]; then
      @termrec@ -p
    else
      command cat "$@"
    fi
  }
fi
