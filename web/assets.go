// Package web contains the dashboard's self-contained templates and assets.
package web

import "embed"

//go:embed *.html *.css *.js
var Assets embed.FS
