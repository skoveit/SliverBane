package handler

import (
	"fmt"
	"strings"

	"sliverbane/internal/engine/vfs"
)

// CommandHandler is used for execute-style (shell command) routing only.
// Protocol-level handlers (ps, ifconfig, env, netstat) are handled directly
// in the engine via proper protobuf messages.
type CommandHandler interface {
	Execute(fs *vfs.SessionFS, args []string) string
}

// Router maps command names to handlers for the execute message type.
type Router struct {
	Handlers map[string]CommandHandler
}

// NewRouter creates a router with filesystem-related command handlers.
func NewRouter() *Router {
	r := &Router{
		Handlers: make(map[string]CommandHandler),
	}
	r.Handlers["ls"] = &LsHandler{}
	r.Handlers["dir"] = &LsHandler{}
	r.Handlers["cd"] = &CdHandler{}
	r.Handlers["pwd"] = &PwdHandler{}
	r.Handlers["cat"] = &CatHandler{}
	r.Handlers["type"] = &CatHandler{}
	r.Handlers["mkdir"] = &MkdirHandler{}
	r.Handlers["rm"] = &RmHandler{}
	r.Handlers["del"] = &RmHandler{}
	r.Handlers["whoami"] = &WhoamiHandler{}
	r.Handlers["id"] = &IdHandler{}
	r.Handlers["hostname"] = &HostnameHandler{}
	r.Handlers["uname"] = &UnameHandler{}
	return r
}

// Route dispatches a command to the appropriate handler.
func (r *Router) Route(fs *vfs.SessionFS, path string, args []string) string {
	cmd := strings.ToLower(filepathBaseName(path))
	if h, ok := r.Handlers[cmd]; ok {
		return h.Execute(fs, args)
	}
	if fs.OS == "windows" {
		return fmt.Sprintf("'%s' is not recognized as an internal or external command,\noperable program or batch file.", cmd)
	}
	return fmt.Sprintf("bash: %s: command not found", cmd)
}

func filepathBaseName(path string) string {
	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	if len(parts) == 0 {
		return path
	}
	return parts[len(parts)-1]
}

// ─── Simple command handlers ─────────────────────────────────────────────────

type WhoamiHandler struct{}

func (h *WhoamiHandler) Execute(fs *vfs.SessionFS, args []string) string {
	if fs.OS == "windows" {
		return fmt.Sprintf("%s\\%s", fs.Hostname, fs.Username)
	}
	return fs.Username
}

type IdHandler struct{}

func (h *IdHandler) Execute(fs *vfs.SessionFS, args []string) string {
	return fmt.Sprintf("uid=%s(%s) gid=%s(%s) groups=%s(%s)", fs.Uid, fs.Username, fs.Gid, fs.Username, fs.Gid, fs.Username)
}

type HostnameHandler struct{}

func (h *HostnameHandler) Execute(fs *vfs.SessionFS, args []string) string {
	return fs.Hostname
}

type UnameHandler struct{}

func (h *UnameHandler) Execute(fs *vfs.SessionFS, args []string) string {
	for _, a := range args {
		if a == "-a" {
			return fmt.Sprintf("Linux %s 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux", fs.Hostname)
		}
	}
	return "Linux"
}
