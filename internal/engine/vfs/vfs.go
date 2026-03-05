package vfs

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"

	"sliverbane/internal/engine/identity"
	"sliverbane/protobuf/sliverpb"

	"github.com/spf13/afero"
)

// SessionFS holds the in-memory filesystem for a single session.
type SessionFS struct {
	Fs       afero.Fs
	CWD      string
	OS       string
	Hostname string
	Username string
	IP       string
	Uid      string
	Gid      string
	Pid      int32
}

// NewSessionFS builds a rich filesystem from the generated identity.
func NewSessionFS(id *identity.Identity) *SessionFS {
	fs := afero.NewMemMapFs()
	s := &SessionFS{
		Fs:       fs,
		OS:       strings.ToLower(id.OS),
		Hostname: id.Hostname,
		Username: id.Username,
		IP:       id.IP,
		Uid:      id.Uid,
		Gid:      id.Gid,
		Pid:      id.Pid,
	}

	if s.OS == "windows" {
		s.populateWindows()
		s.CWD = fmt.Sprintf(`C:\Users\%s`, id.Username)
	} else {
		s.populateLinux()
		s.CWD = id.HomeDir
	}

	return s
}

func (s *SessionFS) Abs(path string) string {
	if path == "" {
		return s.CWD
	}
	if s.OS == "windows" {
		if (len(path) >= 2 && path[1] == ':') || strings.HasPrefix(path, `\`) {
			return path
		}
		return filepath.Join(s.CWD, path)
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(s.CWD, path)
}

func (s *SessionFS) HandleLs(req *sliverpb.LsReq) *sliverpb.Ls {
	target := s.Abs(req.Path)
	entries, err := afero.ReadDir(s.Fs, target)
	if err != nil {
		return &sliverpb.Ls{Path: target, Exists: false, Response: &sliverpb.Response{Err: err.Error()}}
	}

	var files []*sliverpb.FileInfo
	for _, entry := range entries {
		files = append(files, &sliverpb.FileInfo{
			Name:    entry.Name(),
			IsDir:   entry.IsDir(),
			Size:    entry.Size(),
			ModTime: entry.ModTime().Unix(),
			Mode:    entry.Mode().String(),
			Uid:     s.Uid,
			Gid:     s.Gid,
		})
	}

	return &sliverpb.Ls{
		Path:     target,
		Exists:   true,
		Files:    files,
		Response: &sliverpb.Response{},
	}
}

func (s *SessionFS) HandleCd(req *sliverpb.CdReq) error {
	target := s.Abs(req.Path)
	info, err := s.Fs.Stat(target)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory: %s", target)
	}
	s.CWD = target
	return nil
}

func (s *SessionFS) HandlePwd() *sliverpb.Pwd {
	return &sliverpb.Pwd{Path: s.CWD, Response: &sliverpb.Response{}}
}

func (s *SessionFS) HandleMkdir(req *sliverpb.MkdirReq) *sliverpb.Mkdir {
	target := s.Abs(req.Path)
	err := s.Fs.MkdirAll(target, 0755)
	resp := &sliverpb.Mkdir{Path: target, Response: &sliverpb.Response{}}
	if err != nil {
		resp.Response.Err = err.Error()
	}
	return resp
}

func (s *SessionFS) HandleRm(req *sliverpb.RmReq) *sliverpb.Rm {
	target := s.Abs(req.Path)
	var err error
	if req.Recursive {
		err = s.Fs.RemoveAll(target)
	} else {
		err = s.Fs.Remove(target)
	}
	resp := &sliverpb.Rm{Path: target, Response: &sliverpb.Response{}}
	if err != nil {
		resp.Response.Err = err.Error()
	}
	return resp
}

func (s *SessionFS) HandleDownload(req *sliverpb.DownloadReq) *sliverpb.Download {
	target := s.Abs(req.Path)
	info, err := s.Fs.Stat(target)
	if err != nil {
		return &sliverpb.Download{Path: target, Exists: false, Response: &sliverpb.Response{Err: err.Error()}}
	}

	if info.IsDir() {
		return &sliverpb.Download{Path: target, Exists: true, IsDir: true, Response: &sliverpb.Response{}}
	}

	// Read actual VFS content
	data, _ := afero.ReadFile(s.Fs, target)
	return &sliverpb.Download{
		Path:     target,
		Exists:   true,
		Data:     data,
		Response: &sliverpb.Response{},
	}
}

func (s *SessionFS) HandleUpload(req *sliverpb.UploadReq) *sliverpb.Upload {
	target := s.Abs(req.Path)
	if err := afero.WriteFile(s.Fs, target, req.Data, 0644); err != nil {
		return &sliverpb.Upload{Path: target, Response: &sliverpb.Response{Err: err.Error()}}
	}
	return &sliverpb.Upload{Path: target, WrittenFiles: 1, Response: &sliverpb.Response{}}
}

func generateRandomData(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}
