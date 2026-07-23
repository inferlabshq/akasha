package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// bannerArt is a rasterized Kali-inspired figure (ākāśa — the ether). Glyph
// classes carry the color: ░▒ disc, ▓ crescent, █ figure, Ψ†|o gold accents.
const bannerArt = `    .                         *
            .                              *

  *      †        ▒▒▒▒▒▒▒▒▒▒▒        Ψ
         |    ▒▒▒▒▒▒░░░░░░░▒▒▒▒▒▒    |
         ███▒▒▒░░░░░▓░░░░░▓░░░░░▒▒▒███
         ▒▒███░░░░░░░▓▓▓▓▓░░░░░░░███▒▒       .
        ▒▒▒░░███░░░░░██o██░░░░░███░░▒▒▒
       ▒▒▒░░░░░███░░░█████░░░███░░░░░▒▒▒
      ▒▒▒░░░░░░░░███░█████░███░░░░░░░░▒▒▒
 .    ▒▒░░░░░░░░░░███████████░░░░░░░░░░▒▒
      ▒▒░░░░░░░█████████████████░░░░░░░▒▒
      ▒▒░░░░███████████████████████░░░░▒▒     *
      ▒▒█████░░█████████████████░░█████▒▒
      ███░░░░█████████████████████░░░░███
       ▒▒▒░░███████████████████████░░▒▒▒      .
  .     ▒▒▒██░░█████████████████░░██▒▒▒
         ███▒░███████████████████░▒███
           ▒▒█████████████████████▒▒
            ███████████████████████
           █████████████████████████`

const bannerTagline = "local vault engine for AI agents"

func bannerStyle(r rune) string {
	switch r {
	case '░':
		return "\x1b[31m"
	case '▒':
		return "\x1b[2;31m"
	case '▓', 'Ψ', '†', '|', 'o':
		return "\x1b[33m"
	case '.', '*':
		return "\x1b[2m"
	default:
		return ""
	}
}

// printBanner writes the startup banner. Interactive terminals only — under
// launchd or a pipe it stays silent so service logs aren't filled with art.
func printBanner(w io.Writer) {
	f, ok := w.(*os.File)
	if !ok {
		return
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return
	}
	wordmark := "              a  k  a  s  h  a"
	tagline := "      " + bannerTagline
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		fmt.Fprintf(w, "%s\n\n%s\n%s\n\n", bannerArt, wordmark, tagline)
		return
	}
	var b strings.Builder
	style := ""
	for _, r := range bannerArt {
		s := bannerStyle(r)
		if s != style {
			b.WriteString("\x1b[0m")
			if s != "" {
				b.WriteString(s)
			}
			style = s
		}
		b.WriteRune(r)
	}
	b.WriteString("\x1b[0m\n\n")
	b.WriteString("\x1b[33m" + wordmark + "\x1b[0m\n")
	b.WriteString("\x1b[2m" + tagline + "\x1b[0m\n\n")
	fmt.Fprint(w, b.String())
}
