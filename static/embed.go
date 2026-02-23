package static

import "embed"

//go:embed *.css *.js css/*.css
var FS embed.FS
