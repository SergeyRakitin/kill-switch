package frontend

import "embed"

// Assets holds the production frontend built by npm run build.
//
//go:embed all:dist
var Assets embed.FS
