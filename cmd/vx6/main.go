// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

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
