package version

// Version is set at build time with -ldflags.
// Defaults to "dev" for local builds.
var Version = "dev"

// Commit is the short git SHA set at build time with -ldflags.
// Defaults to "unknown" for local builds.
var Commit = "unknown"

// BuildDate is the ISO 8601 UTC build timestamp set at build time with -ldflags.
// Defaults to "unknown" for local builds.
var BuildDate = "unknown"
