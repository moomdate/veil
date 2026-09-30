package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

func (a *app) connectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connect AGENT",
		Short: "Let an AI agent use Veil (claude, cursor, or other)",
		Long: `Register Veil as an MCP server with an agent.

  claude   runs ` + "`claude mcp add`" + ` for Claude Code (all projects)
  cursor   adds Veil to ~/.cursor/mcp.json
  other    prints the MCP config to paste into any other agent`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"claude", "cursor", "other"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := a.broker.Vault(); err != nil {
				return err
			}
			switch args[0] {
			case "claude", "claude-code":
				return a.connectClaude()
			case "cursor":
				return a.connectCursor()
			case "other", "print":
				return a.printConfig()
			}
			return fmt.Errorf("unknown agent %q; choose claude, cursor or other", args[0])
		},
	}
	return cmd
}

func (a *app) serverEntry() map[string]any {
	return map[string]any{"command": a.env.Exe, "args": []string{"mcp"}}
}

func (a *app) connectClaude() error {
	claude, err := a.env.LookPath("claude")
	if err != nil {
		a.ui.warn("Couldn't find the `claude` command. Install Claude Code, or run this yourself:")
		a.ui.printf("  claude mcp add --scope user veil -- %s mcp\n", a.env.Exe)
		return nil
	}
	c := exec.Command(claude, "mcp", "add", "--scope", "user", "veil", "--", a.env.Exe, "mcp")
	c.Stdout, c.Stderr = a.env.Stderr, a.env.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("claude mcp add failed: %w. If Veil is already connected, remove it first with `claude mcp remove veil`", err)
	}
	a.ui.success("Claude Code can now use your secrets through Veil.")
	a.ui.note("Start a new Claude Code session, then try: \"list my secrets\".")
	return nil
}

func (a *app) connectCursor() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".cursor", "mcp.json")
	cfg := map[string]any{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("%s is not valid JSON; fix it or add Veil by hand with `veil connect other`", path)
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	servers["veil"] = a.serverEntry()
	cfg["mcpServers"] = servers
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		return err
	}
	a.ui.success("Added Veil to %s", path)
	a.ui.note("Restart Cursor to pick it up.")
	return nil
}

func (a *app) printConfig() error {
	cfg := map[string]any{"mcpServers": map[string]any{"veil": a.serverEntry()}}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	a.ui.note("Add this to your agent's MCP configuration:")
	a.ui.println(string(out))
	return nil
}
