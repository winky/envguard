package main

import (
	"os"

	"github.com/winky/envguard/cmd"
)

func main() {
	os.Exit(cmd.Run())
}
