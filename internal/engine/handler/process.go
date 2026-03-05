package handler

import (
	"fmt"
	"math/rand"
	"strings"

	"sliverbane/internal/engine/identity"
	"sliverbane/protobuf/sliverpb"
)

// ProcessTable generates and caches a realistic process tree per session.
type ProcessTable struct {
	procs []*sliverpb.Process
}

// NewProcessTable builds a realistic process list once per session.
func NewProcessTable(id *identity.Identity) *ProcessTable {
	pt := &ProcessTable{}
	if strings.ToLower(id.OS) == "windows" {
		pt.buildWindows(id)
	} else {
		pt.buildLinux(id)
	}
	return pt
}

// HandlePs returns the cached Ps protobuf response.
func (pt *ProcessTable) HandlePs() *sliverpb.Ps {
	return &sliverpb.Ps{
		Processes: pt.procs,
		Response:  &sliverpb.Response{},
	}
}

func (pt *ProcessTable) add(pid, ppid int32, exe, owner, arch string, cmdline ...string) {
	pt.procs = append(pt.procs, &sliverpb.Process{
		Pid:          pid,
		Ppid:         ppid,
		Executable:   exe,
		Owner:        owner,
		Architecture: arch,
		CmdLine:      cmdline,
	})
}

func (pt *ProcessTable) buildLinux(id *identity.Identity) {
	arch := "x86_64"
	pt.add(1, 0, "systemd", "root", arch, "/sbin/init")
	pt.add(2, 0, "kthreadd", "root", arch)

	// Kernel threads
	kPid := int32(3)
	kThreads := []string{"rcu_gp", "rcu_par_gp", "kworker/0:0H", "mm_percpu_wq", "ksoftirqd/0", "rcu_sched", "migration/0", "watchdog/0", "cpuhp/0"}
	for _, kt := range kThreads {
		pt.add(kPid, 2, kt, "root", arch)
		kPid++
	}

	// System daemons
	basePid := int32(200 + rand.Intn(100))
	systemServices := []struct {
		exe, owner string
		cmdline    []string
	}{
		{"systemd-journald", "root", []string{"/lib/systemd/systemd-journald"}},
		{"systemd-udevd", "root", []string{"/lib/systemd/systemd-udevd"}},
		{"systemd-resolved", "systemd-resolve", []string{"/lib/systemd/systemd-resolved"}},
		{"systemd-logind", "root", []string{"/lib/systemd/systemd-logind"}},
		{"dbus-daemon", "messagebus", []string{"/usr/bin/dbus-daemon", "--system"}},
		{"rsyslogd", "syslog", []string{"/usr/sbin/rsyslogd", "-n", "-iNONE"}},
		{"cron", "root", []string{"/usr/sbin/cron", "-f"}},
		{"sshd", "root", []string{"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"}},
		{"agetty", "root", []string{"/sbin/agetty", "-o", "-p -- \\u", "--noclear", "tty1", "linux"}},
		{"polkitd", "root", []string{"/usr/lib/policykit-1/polkitd", "--no-debug"}},
	}
	for _, svc := range systemServices {
		pt.add(basePid, 1, svc.exe, svc.owner, arch, svc.cmdline...)
		basePid += int32(1 + rand.Intn(20))
	}

	// Optional services (randomly present)
	optServices := []struct {
		exe, owner string
		cmdline    []string
		chance     int // out of 10
	}{
		{"nginx", "root", []string{"nginx: master process /usr/sbin/nginx"}, 5},
		{"nginx", "www-data", []string{"nginx: worker process"}, 5},
		{"postgres", "postgres", []string{"/usr/lib/postgresql/14/bin/postgres", "-D", "/var/lib/postgresql/14/main"}, 4},
		{"dockerd", "root", []string{"/usr/bin/dockerd", "-H", "fd://"}, 4},
		{"containerd", "root", []string{"/usr/bin/containerd"}, 4},
		{"node", id.Username, []string{"node", "/opt/app/server.js"}, 3},
		{"python3", id.Username, []string{"python3", "/opt/scripts/monitor.py"}, 3},
	}
	for _, svc := range optServices {
		if rand.Intn(10) < svc.chance {
			pt.add(basePid, 1, svc.exe, svc.owner, arch, svc.cmdline...)
			basePid += int32(1 + rand.Intn(30))
		}
	}

	// User SSH session
	sshdPid := basePid
	pt.add(sshdPid, basePid-int32(rand.Intn(100)+50), "sshd", "root", arch, fmt.Sprintf("sshd: %s [priv]", id.Username))
	basePid += int32(1 + rand.Intn(5))
	pt.add(basePid, sshdPid, "sshd", id.Username, arch, fmt.Sprintf("sshd: %s@pts/0", id.Username))
	basePid += int32(1 + rand.Intn(5))
	pt.add(basePid, basePid-1, "bash", id.Username, arch, "-bash")
	basePid += int32(1 + rand.Intn(5))

	// Implant process
	pt.add(id.Pid, basePid-int32(rand.Intn(50)+1), filepathBase(id.Filename), id.Username, arch, id.Filename)

	// Random kworkers
	for i := 0; i < 3+rand.Intn(5); i++ {
		pt.add(basePid+int32(i*3), 2, fmt.Sprintf("kworker/%d:1", rand.Intn(4)), "root", arch)
	}
}

func (pt *ProcessTable) buildWindows(id *identity.Identity) {
	arch := "x86_64"

	// Core system processes
	pt.add(0, 0, "[System Process]", "SYSTEM", arch)
	pt.add(4, 0, "System", "SYSTEM", arch)
	pt.add(88, 4, "Registry", "SYSTEM", arch)
	pt.add(328, 4, "smss.exe", "SYSTEM", arch)
	pt.add(416, 328, "csrss.exe", "SYSTEM", arch)
	pt.add(504, 416, "wininit.exe", "SYSTEM", arch)
	pt.add(512, 328, "csrss.exe", "SYSTEM", arch)
	pt.add(580, 504, "services.exe", "SYSTEM", arch)
	pt.add(592, 504, "lsass.exe", "SYSTEM", arch)
	pt.add(600, 512, "winlogon.exe", "SYSTEM", arch)

	// svchost.exe instances (Windows typically has 10-20)
	svchostPids := []int32{}
	basePid := int32(700)
	svchostCount := 10 + rand.Intn(10)
	for i := 0; i < svchostCount; i++ {
		p := basePid + int32(i*4+rand.Intn(4))
		svchostPids = append(svchostPids, p)
		svcFlags := []string{
			"-k netsvcs", "-k LocalServiceNetworkRestricted", "-k DcomLaunch",
			"-k LocalSystemNetworkRestricted", "-k NetworkService",
			"-k LocalService", "-k UnistackSvcGroup",
		}
		pt.add(p, 580, "svchost.exe", "SYSTEM", arch, "C:\\Windows\\System32\\svchost.exe", svcFlags[rand.Intn(len(svcFlags))])
	}

	// Desktop Window Manager
	dwmPid := basePid + int32(svchostCount*4+20)
	pt.add(dwmPid, svchostPids[0], "dwm.exe", "DWM-1", arch, "\"dwm.exe\"")

	// System services
	svcPid := dwmPid + int32(20+rand.Intn(50))
	systemSvcs := []struct {
		exe, owner string
	}{
		{"spoolsv.exe", "SYSTEM"},
		{"MsMpEng.exe", "SYSTEM"},
		{"SecurityHealthService.exe", "SYSTEM"},
		{"SearchIndexer.exe", "SYSTEM"},
		{"WmiPrvSE.exe", "NETWORK SERVICE"},
		{"dllhost.exe", "SYSTEM"},
		{"taskhostw.exe", "SYSTEM"},
		{"fontdrvhost.exe", "UMFD-1"},
	}
	for _, svc := range systemSvcs {
		pt.add(svcPid, 580, svc.exe, svc.owner, arch)
		svcPid += int32(4 + rand.Intn(20))
	}

	// User processes
	userPid := svcPid + int32(100+rand.Intn(200))
	explorerPid := userPid
	pt.add(explorerPid, 600, "explorer.exe", id.Username, arch, "C:\\Windows\\explorer.exe")
	userPid += int32(4 + rand.Intn(10))

	userApps := []struct {
		exe    string
		chance int
	}{
		{"RuntimeBroker.exe", 8},
		{"ShellExperienceHost.exe", 7},
		{"SearchHost.exe", 7},
		{"StartMenuExperienceHost.exe", 7},
		{"TextInputHost.exe", 6},
		{"chrome.exe", 6},
		{"chrome.exe", 6},
		{"chrome.exe", 6},
		{"Teams.exe", 5},
		{"Outlook.exe", 5},
		{"OneDrive.exe", 5},
		{"SecurityHealthSystray.exe", 7},
		{"PhoneExperienceHost.exe", 4},
		{"ctfmon.exe", 8},
	}
	for _, app := range userApps {
		if rand.Intn(10) < app.chance {
			pt.add(userPid, explorerPid, app.exe, id.Username, arch)
			userPid += int32(4 + rand.Intn(20))
		}
	}

	// Implant process
	pt.add(id.Pid, explorerPid, id.Filename, id.Username, arch, fmt.Sprintf("C:\\Users\\%s\\AppData\\Local\\Temp\\%s", id.Username, id.Filename))

	// conhost for any console
	pt.add(userPid+4, id.Pid, "conhost.exe", id.Username, arch, "\\\\?\\C:\\Windows\\system32\\conhost.exe")
}

func filepathBase(path string) string {
	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	if len(parts) == 0 {
		return path
	}
	return parts[len(parts)-1]
}
