// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the VX6 terms in LICENSE-COMMERCIAL.md.
// Sole inventor, maintainer, and rights holder: Suryansh Deshwal (https://github.com/ethical-buddy).

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/vx6/vx6/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), notifySignals()...)
	defer stop()

	if err := cli.Run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vx6:", err)
		os.Exit(1)
	}
}
