package handler

import (
	"fmt"
	"strings"

	"sliverbane/internal/engine/vfs"
	"sliverbane/protobuf/sliverpb"
)

// ─── Filesystem command handlers (for execute routing) ───────────────────────

type LsHandler struct{}

func (h *LsHandler) Execute(fs *vfs.SessionFS, args []string) string {
	path := ""
	if len(args) > 0 {
		path = args[0]
	}
	res := fs.HandleLs(&sliverpb.LsReq{Path: path})
	if !res.Exists {
		return fmt.Sprintf("ls: cannot access '%s': %s", path, res.Response.Err)
	}
	var b strings.Builder
	for _, f := range res.Files {
		indicator := ""
		if f.IsDir {
			indicator = "/"
		}
		b.WriteString(fmt.Sprintf("%s%s\n", f.Name, indicator))
	}
	return b.String()
}

type CdHandler struct{}

func (h *CdHandler) Execute(fs *vfs.SessionFS, args []string) string {
	if len(args) == 0 {
		return ""
	}
	err := fs.HandleCd(&sliverpb.CdReq{Path: args[0]})
	if err != nil {
		return fmt.Sprintf("cd: %s", err.Error())
	}
	return ""
}

type PwdHandler struct{}

func (h *PwdHandler) Execute(fs *vfs.SessionFS, args []string) string {
	return fs.HandlePwd().Path
}

type CatHandler struct{}

func (h *CatHandler) Execute(fs *vfs.SessionFS, args []string) string {
	if len(args) == 0 {
		return "Missing file argument"
	}
	res := fs.HandleDownload(&sliverpb.DownloadReq{Path: args[0]})
	if !res.Exists {
		return fmt.Sprintf("cat: %s: No such file or directory", args[0])
	}
	if res.IsDir {
		return fmt.Sprintf("cat: %s: Is a directory", args[0])
	}
	return string(res.Data)
}

type MkdirHandler struct{}

func (h *MkdirHandler) Execute(fs *vfs.SessionFS, args []string) string {
	if len(args) == 0 {
		return "Missing directory name"
	}
	res := fs.HandleMkdir(&sliverpb.MkdirReq{Path: args[0]})
	if res.Response.Err != "" {
		return res.Response.Err
	}
	return ""
}

type RmHandler struct{}

func (h *RmHandler) Execute(fs *vfs.SessionFS, args []string) string {
	if len(args) == 0 {
		return "Missing file/directory name"
	}
	res := fs.HandleRm(&sliverpb.RmReq{Path: args[0]})
	if res.Response.Err != "" {
		return res.Response.Err
	}
	return ""
}
