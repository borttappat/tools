# slides

A shell for giving terminal presentations with
[slides](https://github.com/maaslalani/slides), themed from your current
[pywal](https://github.com/dylanaraps/pywal) colors if you have any.

```bash
nix run "github:borttappat/tools?dir=slides"
```

This opens your own `$SHELL` in the current directory with the tools on
`PATH` and prints a short help text. Inside the shell:

| Command | What it does |
|---|---|
| `present <file.md>` | Presents a markdown file |
| `slides-help` | Prints the help text again |
| `exit` | Leaves the shell |

To present a file directly without the shell:

```bash
nix run "github:borttappat/tools?dir=slides#present" -- talk.md
```

## Theming

Every time you run `present` or `slides`, the theme is rebuilt from
`~/.cache/wal/colors.json`. That means if you run `wal` in the middle of a
session, the next presentation picks up the new colors. Headings, code,
quotes, links and emphasis use `color1` to `color7`. The page itself uses
wal's background and foreground.

slides has no setting for its status-bar color, so it is changed in the
program file itself. A copy of `slides` has the color `#E8B4BC` swapped for
wal's foreground (both are 7 bytes, so the program still runs). That copy is
kept in the cache and only made again when the color or slides version
changes.

The theme and the changed copy are saved to `~/.cache/slides-shell/`
(`$XDG_CACHE_HOME` is used if set), so nothing is written next to your
presentation.

If there is no wal colors file, slides uses its own default theme. Set
`WAL_COLORS` to use a different colors file.
