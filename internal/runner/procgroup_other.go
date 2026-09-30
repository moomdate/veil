//go:build !unix

package runner

import "os/exec"

func setProcessGroup(*exec.Cmd) {}
