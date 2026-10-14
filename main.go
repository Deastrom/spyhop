package main

import (
	"os"

	"github.com/Deastrom/spyhop/cmd"
	"github.com/Deastrom/spyhop/internal/mcp"
)

// version is set at build time via -ldflags "-X main.version=x.y.z".
var version = "dev"

func main() {
	mcp.Version = version
	os.Exit(cmd.ExitCode(&cmd.App{Out: os.Stdout, Err: os.Stderr, In: os.Stdin, Getenv: os.Getenv, Version: version}, os.Args[1:]))
}
