// Command privasimu-bridge is the Privasimu data discovery bridge: it runs inside the
// client's network, reads database catalogs and file shares, and reports only names,
// types, personal-data categories, counts and confidence to Privasimu.
package main

import (
	"os"
	"strconv"

	"github.com/privasimu/bridge/internal/cli"
	"github.com/privasimu/bridge/internal/files"
)

func main() {
	// The PDF extractor runs the bridge itself as a short-lived child process.
	if len(os.Args) == 4 && os.Args[1] == files.ChildCommand {
		maxIn, err1 := strconv.ParseInt(os.Args[2], 10, 64)
		maxOut, err2 := strconv.ParseInt(os.Args[3], 10, 64)
		if err1 != nil || err2 != nil || maxIn <= 0 || maxOut <= 0 {
			os.Exit(64)
		}
		os.Exit(files.RunChild(os.Stdin, os.Stdout, maxIn, maxOut))
	}
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
