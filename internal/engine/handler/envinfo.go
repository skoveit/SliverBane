package handler

import (
	"fmt"
	"strings"

	"sliverbane/internal/engine/identity"
	"sliverbane/protobuf/sliverpb"
)

// EnvTable provides realistic environment variables per session.
type EnvTable struct {
	vars []*sliverpb.EnvVar
}

// NewEnvTable builds a realistic environment for the session.
func NewEnvTable(id *identity.Identity) *EnvTable {
	et := &EnvTable{}
	if strings.ToLower(id.OS) == "windows" {
		et.buildWindows(id)
	} else {
		et.buildLinux(id)
	}
	return et
}

// HandleEnv returns the full or filtered EnvInfo protobuf response.
func (et *EnvTable) HandleEnv(req *sliverpb.EnvReq) *sliverpb.EnvInfo {
	if req.Name != "" {
		// Return specific var
		for _, v := range et.vars {
			if strings.EqualFold(v.Key, req.Name) {
				return &sliverpb.EnvInfo{
					Variables: []*sliverpb.EnvVar{v},
					Response:  &sliverpb.Response{},
				}
			}
		}
		return &sliverpb.EnvInfo{Response: &sliverpb.Response{}}
	}
	return &sliverpb.EnvInfo{
		Variables: et.vars,
		Response:  &sliverpb.Response{},
	}
}

func (et *EnvTable) buildLinux(id *identity.Identity) {
	home := id.HomeDir
	et.vars = []*sliverpb.EnvVar{
		{Key: "PATH", Value: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"},
		{Key: "HOME", Value: home},
		{Key: "USER", Value: id.Username},
		{Key: "LOGNAME", Value: id.Username},
		{Key: "SHELL", Value: "/bin/bash"},
		{Key: "LANG", Value: "en_US.UTF-8"},
		{Key: "LC_ALL", Value: "en_US.UTF-8"},
		{Key: "TERM", Value: "xterm-256color"},
		{Key: "HOSTNAME", Value: id.Hostname},
		{Key: "PWD", Value: home},
		{Key: "OLDPWD", Value: home},
		{Key: "SHLVL", Value: "1"},
		{Key: "SSH_CLIENT", Value: fmt.Sprintf("10.0.0.50 54321 22")},
		{Key: "SSH_CONNECTION", Value: fmt.Sprintf("10.0.0.50 54321 %s 22", id.IP)},
		{Key: "SSH_TTY", Value: "/dev/pts/0"},
		{Key: "XDG_SESSION_ID", Value: "3"},
		{Key: "XDG_SESSION_TYPE", Value: "tty"},
		{Key: "XDG_RUNTIME_DIR", Value: fmt.Sprintf("/run/user/%s", id.Uid)},
		{Key: "MAIL", Value: fmt.Sprintf("/var/mail/%s", id.Username)},
		{Key: "_", Value: "/usr/bin/env"},
	}
}

func (et *EnvTable) buildWindows(id *identity.Identity) {
	et.vars = []*sliverpb.EnvVar{
		{Key: "ALLUSERSPROFILE", Value: `C:\ProgramData`},
		{Key: "APPDATA", Value: fmt.Sprintf(`C:\Users\%s\AppData\Roaming`, id.Username)},
		{Key: "CommonProgramFiles", Value: `C:\Program Files\Common Files`},
		{Key: "CommonProgramFiles(x86)", Value: `C:\Program Files (x86)\Common Files`},
		{Key: "CommonProgramW6432", Value: `C:\Program Files\Common Files`},
		{Key: "COMPUTERNAME", Value: strings.ToUpper(id.Hostname)},
		{Key: "ComSpec", Value: `C:\Windows\system32\cmd.exe`},
		{Key: "HOMEDRIVE", Value: "C:"},
		{Key: "HOMEPATH", Value: fmt.Sprintf(`\Users\%s`, id.Username)},
		{Key: "LOCALAPPDATA", Value: fmt.Sprintf(`C:\Users\%s\AppData\Local`, id.Username)},
		{Key: "LOGONSERVER", Value: fmt.Sprintf(`\\%s`, strings.ToUpper(id.Hostname))},
		{Key: "NUMBER_OF_PROCESSORS", Value: "4"},
		{Key: "OS", Value: "Windows_NT"},
		{Key: "Path", Value: `C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Program Files\7-Zip`},
		{Key: "PATHEXT", Value: `.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL`},
		{Key: "PROCESSOR_ARCHITECTURE", Value: "AMD64"},
		{Key: "PROCESSOR_IDENTIFIER", Value: "Intel64 Family 6 Model 85 Stepping 7, GenuineIntel"},
		{Key: "PROCESSOR_LEVEL", Value: "6"},
		{Key: "PROCESSOR_REVISION", Value: "5507"},
		{Key: "ProgramData", Value: `C:\ProgramData`},
		{Key: "ProgramFiles", Value: `C:\Program Files`},
		{Key: "ProgramFiles(x86)", Value: `C:\Program Files (x86)`},
		{Key: "ProgramW6432", Value: `C:\Program Files`},
		{Key: "PSModulePath", Value: fmt.Sprintf(`C:\Users\%s\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules`, id.Username)},
		{Key: "PUBLIC", Value: `C:\Users\Public`},
		{Key: "SystemDrive", Value: "C:"},
		{Key: "SystemRoot", Value: `C:\Windows`},
		{Key: "TEMP", Value: fmt.Sprintf(`C:\Users\%s\AppData\Local\Temp`, id.Username)},
		{Key: "TMP", Value: fmt.Sprintf(`C:\Users\%s\AppData\Local\Temp`, id.Username)},
		{Key: "USERDOMAIN", Value: strings.ToUpper(id.Hostname)},
		{Key: "USERDOMAIN_ROAMINGPROFILE", Value: strings.ToUpper(id.Hostname)},
		{Key: "USERNAME", Value: id.Username},
		{Key: "USERPROFILE", Value: fmt.Sprintf(`C:\Users\%s`, id.Username)},
		{Key: "windir", Value: `C:\Windows`},
	}
}
