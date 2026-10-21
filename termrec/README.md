# termrec

Records every interactive terminal with [asciinema](https://asciinema.org), so
command output is never lost, and lets you name a session while it runs and
read it back as plain text. Works in bash, zsh and fish.

- Each terminal records to `<timestamp>-<hex>.cast` in `$TERMREC_DIR`
  (default `~/terminal_logs`).
- When the terminal closes, the recording is also written as a plain-text
  transcript (`.txt`). `asciinema convert` emulates a terminal, so prompts,
  line editing and redraws come out as readable lines.
- `rec -r NAME` renames the running session, so it is easy to find and read
  later.

## Try it

Opens a recorded shell with only termrec loaded, none of your own shell config.
Recordings go to a temporary directory, so nothing in your home changes:

```bash
nix run "github:borttappat/tools?dir=termrec"            # your $SHELL if bash/zsh/fish, else bash
nix run "github:borttappat/tools?dir=termrec" -- zsh     # or pick one: bash, zsh, fish
```

Exit the shell to end the demo; it lists what was recorded and where.

A shell with termrec, the demo, the test and all three shells:

```bash
nix develop "github:borttappat/tools?dir=termrec"
```

## Commands

In a recorded shell, `rec` is short for `termrec`:

| Command | Purpose |
|---------|---------|
| `rec` / `rec -c` | Show the current session's name and path |
| `rec -l` | List sessions, oldest first (`*` marks this terminal) |
| `rec -r NAME` | Rename the current session to `NAME.cast` (its `.txt` follows on exit) |
| `rec -p [SESSION]` | Print one session as text (default: current), framed by `==> name <==` lines on a terminal |
| `rec -a` | Print every session as text |
| `rec -x` | End the current recording and continue in a plain, unrecorded shell (also `stop-recording`) |
| `rec -s` | Begin a fresh recording in the current terminal (also `start-recording`) |

`rec -x` and `rec -s` end or replace the shell itself, so they work through
`rec` (a shell function), not the `termrec` program. Printing the session you
are in adds that output to the recording too.

`SESSION` is a name, any unique part of one, or a path. Renaming a live session
is safe: asciinema keeps writing to the renamed file. `cat` of the live
recording prints the text render instead of feeding the growing file back into
itself; every other `cat` is unchanged.

Not recorded: non-interactive shells, the Linux console (`TERM=linux`),
`TERM=dumb`, shells started inside a recorded shell, and any shell with
`TERMREC_DISABLE` set.

## Install

### NixOS

```nix
# flake.nix inputs
termrec.url = "github:borttappat/tools?dir=termrec";

# configuration
imports = [ inputs.termrec.nixosModules.default ];
programs.termrec = {
  enable = true;
  dir = "$HOME/terminal_logs";      # optional, TERMREC_DIR
  shells = [ "bash" "zsh" "fish" ]; # default: all three
};
```

The snippet goes first in each shell's system-wide interactive init, so a new
terminal starts recording before your own config runs.

### Any shell, by hand

Put `termrec` on your PATH (`nix profile install "github:borttappat/tools?dir=termrec"`),
then load the snippet early in your shell config:

```bash
eval "$(termrec init bash)"   # ~/.bashrc
eval "$(termrec init zsh)"    # ~/.zshrc
```

```fish
termrec init fish | source    # ~/.config/fish/config.fish
```

### Prompt indicator

`$TERMREC_FILE` is set in recorded shells. With starship:

```toml
[env_var.TERMREC]
variable = "TERMREC_FILE"
format = '[\[REC\]]($style) '
style = "bold red"
```

## How it works

The snippet execs `termrec session` when an interactive terminal opens. That runs
`asciinema rec` around a fresh copy of the same shell, which sees `$TERMREC` and
does not record again. The current session's path is kept in a state file under
`$XDG_RUNTIME_DIR`, not in the shell's environment, so a rename is seen by every
later lookup and by the final text conversion. `stop-recording` leaves a marker
and exits the recorded shell; `termrec session` sees the marker and continues in
a plain shell instead of closing the terminal.

## Test

```bash
nix flake check "github:borttappat/tools?dir=termrec"
nix run "github:borttappat/tools?dir=termrec#test" -- bash   # or zsh, fish; default all
```

The test drives real interactive bash, zsh and fish sessions through a pty
(util-linux `script`), the way a terminal would, and checks recording, renaming,
the transcript, the `cat` guard, `stop-recording`/`start-recording` and every
`rec` listing and printing command. It types with short pauses, so a heavily
loaded machine can make it flaky.
