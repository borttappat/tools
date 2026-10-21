# termrec for fish: record every interactive terminal.
# Load with: termrec init fish | source  (early in ~/.config/fish/config.fish).

if status is-interactive; and test -t 1; and not set -q TERMREC; and not set -q TERMREC_DISABLE; \
        and set -q TERM; and not contains -- "$TERM" dumb linux
    set -q TERMREC_SHELL; or set -gx TERMREC_SHELL (status fish-path)
    exec @termrec@ session
end

# rec: termrec, plus -x/-s, which have to run in this shell to end or replace it.
function rec --description "Terminal recordings (termrec)"
    switch "$argv[1]"
        case -x stop
            stop-recording
        case -s start
            start-recording
        case '*'
            @termrec@ $argv
    end
end

# Toggle the recorder without closing the terminal: stop ends the current
# recording and drops to a plain shell; start begins a fresh recording.
function stop-recording --description "Stop recording this terminal"
    if not set -q TERMREC_STOP
        echo "Not recording."
        return 1
    end
    command touch $TERMREC_STOP
    exit
end
function start-recording --description "Start recording this terminal"
    if set -q TERMREC_STOP
        echo "Already recording: "(@termrec@ -c)
        return 1
    end
    set -e TERMREC
    exec @termrec@ session
end

# `cat`-ing the live recording would feed its own output back into the growing
# file and loop; show a clean text render instead. Every other `cat` passes
# straight through.
if set -q TERMREC_STATE
    function cat
        if test (count $argv) -eq 1; and test -f "$TERMREC_STATE"
            read -l cur <$TERMREC_STATE
            set -l arg (command realpath -- $argv[1] 2>/dev/null)
            if test "$arg" = "$cur"
                @termrec@ -p
                return
            end
        end
        command cat $argv
    end
end
