//go:build !windows

package ui

import "os/exec"

func configureCommand(cmd *exec.Cmd) {}
