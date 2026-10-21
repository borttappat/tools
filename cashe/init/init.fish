# cashe for fish: record every interactive terminal.
# Load with: cashe init fish | source  (early in ~/.config/fish/config.fish).

if status is-interactive; and test -t 1; and not set -q CASHE; and not set -q CASHE_DISABLE; \
        and set -q TERM; and not contains -- "$TERM" dumb linux
    set -q CASHE_SHELL; or set -gx CASHE_SHELL (status fish-path)
    exec @cashe@ session
end

# rec: cashe, plus -x/-s, which have to run in this shell to end or replace it.
function rec --description "Terminal recordings (cashe)"
    switch "$argv[1]"
        case -x stop
            stop-recording
        case -s start
            start-recording
        case '*'
            @cashe@ $argv
    end
end

# Toggle the recorder without closing the terminal: stop ends the current
# recording and drops to a plain shell; start begins a fresh recording.
function stop-recording --description "Stop recording this terminal"
    if not set -q CASHE_STOP
        echo "Not recording."
        return 1
    end
    command touch $CASHE_STOP
    exit
end
function start-recording --description "Start recording this terminal"
    if set -q CASHE_STOP
        echo "Already recording: "(@cashe@ -c)
        return 1
    end
    set -e CASHE
    exec @cashe@ session
end

# `cat`-ing the live recording would feed its own output back into the growing
# file and loop; show a clean text render instead. Every other `cat` passes
# straight through.
if set -q CASHE_STATE
    function cat
        if test (count $argv) -eq 1; and test -f "$CASHE_STATE"
            read -l cur <$CASHE_STATE
            set -l arg (command realpath -- $argv[1] 2>/dev/null)
            if test "$arg" = "$cur"
                @cashe@ -p
                return
            end
        end
        command cat $argv
    end
end
