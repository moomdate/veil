// Package mcpserver exposes Veil to AI agents over the Model Context
// Protocol. It offers exactly three tools and none of them returns a
// secret's value:
//
//   - list_secrets: names, descriptions and rules
//   - run_with_secrets: run a command with secrets as environment variables
//   - http_request: send a request with {{secret:NAME}} placeholders
package mcpserver

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/moomdate/veil/internal/broker"
	"github.com/moomdate/veil/internal/httpinject"
	"github.com/moomdate/veil/internal/runner"
)

const instructions = `Veil lets you use the user's secrets (API keys, tokens, passwords) without seeing them.
Call list_secrets first. Never ask the user to paste a secret into the chat; if one you need is missing, ask them to add it with ` + "`veil add NAME`" + `.
Output that contains a secret shows [HIDDEN:NAME] instead. Don't try to reveal or transform secret values; Veil logs every use.`

// New returns an MCP server backed by b.
func New(b *broker.Broker, version string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "veil", Title: "Veil", Version: version}, &mcp.ServerOptions{
		Instructions: instructions,
	})
	h := handlers{b: b}

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_secrets",
		Title:       "List secrets",
		Description: "List the secrets you can use: name, what it's for, its protection, and how to use it. Values are never returned.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, h.list)

	mcp.AddTool(s, &mcp.Tool{
		Name:  "run_with_secrets",
		Title: "Run a command with secrets",
		Description: "Run a command with Basic secrets available as environment variables named after the secret " +
			"(for example $GITHUB_TOKEN). argv is run directly, not through a shell; to use shell features pass " +
			`["sh","-c","..."] if the secret allows it. Any secret value in the output is replaced with [HIDDEN:NAME].`,
	}, h.run)

	mcp.AddTool(s, &mcp.Tool{
		Name:  "http_request",
		Title: "Send an HTTP request with secrets",
		Description: "Send an HTTPS request, writing {{secret:NAME}} where a Scoped secret's value should go " +
			`(for example the header "Authorization": "Bearer {{secret:STRIPE_SECRET_KEY}}"). ` +
			"Veil only fills it in if the URL's host is allowed for that secret. Redirects are not followed.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(true)},
	}, h.http)

	return s
}

type handlers struct{ b *broker.Broker }

type listIn struct{}

type listOut struct {
	Secrets []broker.Info `json:"secrets"`
	Hint    string        `json:"hint,omitempty"`
}

func (h handlers) list(_ context.Context, _ *mcp.CallToolRequest, _ listIn) (*mcp.CallToolResult, listOut, error) {
	infos, err := h.b.List()
	if err != nil {
		return nil, listOut{}, err
	}
	out := listOut{Secrets: infos}
	if len(infos) == 0 {
		out.Hint = "No secrets yet. Ask the user to add one with `veil add NAME`."
		out.Secrets = []broker.Info{}
	}
	return nil, out, nil
}

type runIn struct {
	Secrets        []string `json:"secrets" jsonschema:"names of the secrets to put in the environment"`
	Argv           []string `json:"argv" jsonschema:"the command and its arguments, for example [\"gh\",\"pr\",\"create\",\"--fill\"]"`
	Dir            string   `json:"dir,omitempty" jsonschema:"working directory; defaults to where Veil was started"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"stop the command after this many seconds (default 120, max 600)"`
}

func (h handlers) run(ctx context.Context, req *mcp.CallToolRequest, in runIn) (*mcp.CallToolResult, runner.Result, error) {
	res, err := h.b.Run(ctx, broker.RunRequest{
		Agent:   agentName(req),
		Secrets: in.Secrets,
		Argv:    in.Argv,
		Dir:     in.Dir,
		Timeout: time.Duration(in.TimeoutSeconds) * time.Second,
	})
	return nil, res, err
}

type httpIn struct {
	Method  string            `json:"method,omitempty" jsonschema:"HTTP method (default GET)"`
	URL     string            `json:"url" jsonschema:"full URL; {{secret:NAME}} may appear in the path or query but not the host"`
	Headers map[string]string `json:"headers,omitempty" jsonschema:"request headers; values may contain {{secret:NAME}}"`
	Body    string            `json:"body,omitempty" jsonschema:"request body; may contain {{secret:NAME}}"`
}

func (h handlers) http(ctx context.Context, req *mcp.CallToolRequest, in httpIn) (*mcp.CallToolResult, httpinject.Response, error) {
	res, err := h.b.HTTP(ctx, agentName(req), httpinject.Request{
		Method: in.Method, URL: in.URL, Headers: in.Headers, Body: in.Body,
	})
	return nil, res, err
}

func agentName(req *mcp.CallToolRequest) string {
	if req != nil {
		if info := req.ClientInfo(); info != nil && info.Name != "" {
			return info.Name
		}
	}
	return "unknown agent"
}

func ptr[T any](v T) *T { return &v }
