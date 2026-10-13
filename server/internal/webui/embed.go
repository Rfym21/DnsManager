// Package webui provides the React assets embedded in the Go executable.
package webui

import (
	"embed"
	"io/fs"
)

// Build web/ before compiling Go so dist contains the current React assets.
//
//go:embed all:dist
var assets embed.FS

// Files returns the embedded frontend filesystem rooted at its index.html.
func Files() fs.FS {
	files, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err) // The embedded directory is checked by the Go compiler.
	}
	return files
}
