{
  description = "slides - terminal presentation shell themed from pywal colors";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};

      # Theme and patched binary live in the user's cache, never next to the
      # presentation, so pointing the shell at a repo leaves it untouched.
      cacheEnv = ''
        WAL="''${WAL_COLORS:-$HOME/.cache/wal/colors.json}"
        CACHE="''${XDG_CACHE_HOME:-$HOME/.cache}/slides-shell"
        THEME="$CACHE/theme.json"
        mkdir -p "$CACHE/bin"
      '';

      # Glamour style JSON built from wal: color0-15 + bg + fg + cursor, with
      # any color16+ from non-standard backends cycled from those base 19.
      generateTheme = ''
        ${pkgs.jq}/bin/jq '
          (.special) as $sp |
          (.colors) as $c |
          [
            $c.color0,  $c.color1,  $c.color2,  $c.color3,
            $c.color4,  $c.color5,  $c.color6,  $c.color7,
            $c.color8,  $c.color9,  $c.color10, $c.color11,
            $c.color12, $c.color13, $c.color14, $c.color15,
            $sp.background, $sp.foreground, $sp.cursor
          ] as $base19 |
          ($c | to_entries
              | sort_by(.key | ltrimstr("color") | tonumber)
              | map(.value)) as $all |
          ($all | length) as $total |
          (if $total <= 16 then $base19
           else $base19 + [ range(16; $total) | . as $i | $base19[$i % 19] ]
           end) as $colors |
          {
            document:    { color: $sp.foreground, background_color: $sp.background, margin: 4 },
            block_quote: { color: $c.color5, indent: 2, indent_token: "│ " },
            h1:          { prefix: "  ", suffix: "  ", color: $c.color4, background_color: $sp.background, bold: true },
            h2:          { prefix: "▌ ", color: $c.color3, bold: true },
            h3:          { prefix: "  ", color: $c.color2 },
            h4:          { prefix: "   ", color: $c.color1 },
            code:        { color: $c.color3, background_color: $sp.background },
            code_block:  { color: $c.color7, background_color: $sp.background, margin: 2 },
            strong:      { color: $c.color4, bold: true },
            emph:        { color: $c.color5, italic: true },
            link:        { color: $c.color2 },
            link_text:   { color: $c.color1, bold: true },
            table:       { center_separator: "┼", column_separator: "│", row_separator: "─" },
            hr:          { format: "\n────────────────────────────────────────\n" },
            item:        { block_prefix: "• " },
            enumeration: { block_prefix: ". " },
            colors:      $colors
          }
        ' "$WAL" > "$THEME.tmp" && mv "$THEME.tmp" "$THEME"
      '';

      # slides hardcodes its status-bar color as the literal "#E8B4BC". Swap
      # it for wal's foreground in a cached copy of the binary; both strings
      # are exactly 7 bytes, so the binary stays valid. Re-copied only when
      # the color or the upstream binary changes.
      patchBinary = ''
        STATUS_COLOR=$(${pkgs.jq}/bin/jq -r '.special.foreground' "$WAL")
        PATCHED="$CACHE/bin/slides"
        STAMP="${pkgs.slides} $STATUS_COLOR"
        if [[ "$STATUS_COLOR" =~ ^#[0-9A-Fa-f]{6}$ ]]; then
          if [ ! -x "$PATCHED" ] || [ "$(cat "$CACHE/bin/stamp" 2>/dev/null)" != "$STAMP" ]; then
            cp "${pkgs.slides}/bin/slides" "$PATCHED.tmp"
            chmod u+w "$PATCHED.tmp"
            LC_ALL=C ${pkgs.gnused}/bin/sed -i "s/#E8B4BC/$STATUS_COLOR/g" "$PATCHED.tmp"
            chmod +x "$PATCHED.tmp"
            mv "$PATCHED.tmp" "$PATCHED"
            echo "$STAMP" > "$CACHE/bin/stamp"
          fi
          SLIDES_BIN="$PATCHED"
        fi
      '';

      # Shadows the real slides on PATH inside the shell. Regenerates the
      # theme on every run, so a wal change mid-session is picked up by the
      # next presentation with no manual step.
      slidesWrapper = pkgs.writeShellScriptBin "slides" ''
        set -e
        SLIDES_BIN="${pkgs.slides}/bin/slides"
        ${cacheEnv}
        if [ -f "$WAL" ]; then
          ${generateTheme}
          ${patchBinary}
          export GLAMOUR_STYLE="$THEME"
        fi
        exec "$SLIDES_BIN" "$@"
      '';

      present = pkgs.writeShellScriptBin "present" ''
        FILE="''${1:-$SLIDES_DEFAULT_FILE}"
        if [ -z "$FILE" ]; then
          echo "Usage: present <file.md>" >&2
          exit 1
        fi
        if [ ! -f "$FILE" ]; then
          echo "Error: $FILE not found" >&2
          exit 1
        fi
        exec ${slidesWrapper}/bin/slides "$FILE"
      '';

      slidesHelp = pkgs.writeShellScriptBin "slides-help" ''
        WAL="''${WAL_COLORS:-$HOME/.cache/wal/colors.json}"
        echo ""
        echo "  slides shell ready"
        if [ -f "$WAL" ]; then
          echo "  theme: wal colors from $WAL (re-read on every run)"
        else
          echo "  theme: slides default ($WAL not found)"
        fi
        echo ""
        if [ -n "$SLIDES_DEFAULT_FILE" ]; then
          echo "  run:  present                (default: $SLIDES_DEFAULT_FILE)"
        fi
        echo "  run:  present <file.md>      (any markdown file)"
        echo "  run:  slides-help            (show this again)"
        echo "  run:  exit                   (leave the shell)"
        echo ""
      '';

      # Entry point for `nix run`: optional path to a markdown file or a
      # directory. A file becomes present's default; either way the shell
      # starts in its directory. Execs the user's own $SHELL, so prompt,
      # aliases and terminal colors are untouched.
      slidesShell = pkgs.writeShellScriptBin "slides-shell" ''
        set -e
        TARGET="''${1:-.}"
        if [ -d "$TARGET" ]; then
          cd "$TARGET"
          unset SLIDES_DEFAULT_FILE
        elif [ -f "$TARGET" ]; then
          cd "$(dirname "$TARGET")"
          export SLIDES_DEFAULT_FILE="$(basename "$TARGET")"
        else
          echo "Error: $TARGET is neither a file nor a directory" >&2
          exit 1
        fi
        export PATH="${slidesWrapper}/bin:${present}/bin:${slidesHelp}/bin:$PATH"
        export SLIDES_SHELL=1
        slides-help
        exec "''${SHELL:-${pkgs.bashInteractive}/bin/bash}"
      '';
    in {
      packages.default = slidesShell;

      apps = {
        default = flake-utils.lib.mkApp {
          drv = slidesShell;
          exePath = "/bin/slides-shell";
        };
        present = flake-utils.lib.mkApp {
          drv = present;
          exePath = "/bin/present";
        };
      };

      devShells.default = pkgs.mkShell {
        name = "slides";
        buildInputs = [slidesWrapper present slidesHelp];
        shellHook = "slides-help";
      };
    });
}
