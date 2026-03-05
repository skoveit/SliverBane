package vfs

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/spf13/afero"
)

func (s *SessionFS) populateWindows() {
	now := time.Now()

	// ─── Core directories ────────────────────────────────────────────
	dirs := []string{
		`C:\Windows`, `C:\Windows\System32`, `C:\Windows\System32\config`,
		`C:\Windows\System32\drivers`, `C:\Windows\System32\drivers\etc`,
		`C:\Windows\System32\wbem`, `C:\Windows\System32\WindowsPowerShell\v1.0`,
		`C:\Windows\SysWOW64`, `C:\Windows\Temp`,
		`C:\Windows\Prefetch`, `C:\Windows\Logs`,
		`C:\Windows\Microsoft.NET\Framework64\v4.0.30319`,
		`C:\Program Files`, `C:\Program Files\Common Files`,
		`C:\Program Files\Windows Defender`,
		`C:\Program Files\Microsoft Office`, `C:\Program Files\Microsoft Office\root\Office16`,
		`C:\Program Files\Google`, `C:\Program Files\Google\Chrome\Application`,
		`C:\Program Files\7-Zip`,
		`C:\Program Files (x86)`, `C:\Program Files (x86)\Common Files`,
		`C:\Program Files (x86)\Microsoft`,
		`C:\ProgramData`, `C:\ProgramData\Microsoft\Windows\Start Menu\Programs`,
		fmt.Sprintf(`C:\Users\%s`, s.Username),
		fmt.Sprintf(`C:\Users\%s\Desktop`, s.Username),
		fmt.Sprintf(`C:\Users\%s\Documents`, s.Username),
		fmt.Sprintf(`C:\Users\%s\Downloads`, s.Username),
		fmt.Sprintf(`C:\Users\%s\Pictures`, s.Username),
		fmt.Sprintf(`C:\Users\%s\Music`, s.Username),
		fmt.Sprintf(`C:\Users\%s\Videos`, s.Username),
		fmt.Sprintf(`C:\Users\%s\AppData\Local`, s.Username),
		fmt.Sprintf(`C:\Users\%s\AppData\Local\Temp`, s.Username),
		fmt.Sprintf(`C:\Users\%s\AppData\Local\Microsoft\Windows\Explorer`, s.Username),
		fmt.Sprintf(`C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default`, s.Username),
		fmt.Sprintf(`C:\Users\%s\AppData\Roaming`, s.Username),
		fmt.Sprintf(`C:\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs`, s.Username),
		fmt.Sprintf(`C:\Users\%s\AppData\Roaming\Microsoft\Windows\Recent`, s.Username),
		`C:\Users\Public`, `C:\Users\Public\Desktop`, `C:\Users\Public\Documents`,
		`C:\Recovery`, `C:\$Recycle.Bin`,
		`C:\inetpub\wwwroot`,
	}
	for _, d := range dirs {
		s.Fs.MkdirAll(d, 0755)
	}

	user := s.Username

	// ─── System files ────────────────────────────────────────────────
	writeFile(s, `C:\Windows\System32\drivers\etc\hosts`, `# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
127.0.0.1       localhost
::1             localhost
`)

	writeFile(s, `C:\Windows\System32\config\SAM`, "")    // exists but unreadable
	writeFile(s, `C:\Windows\System32\config\SYSTEM`, "") // exists but unreadable
	writeFile(s, `C:\Windows\System32\config\SOFTWARE`, "")

	// System DLLs (stubs with realistic sizes)
	dlls := map[string]int{
		`C:\Windows\System32\ntdll.dll`:                             1900000 + rand.Intn(200000),
		`C:\Windows\System32\kernel32.dll`:                          800000 + rand.Intn(100000),
		`C:\Windows\System32\user32.dll`:                            1600000 + rand.Intn(200000),
		`C:\Windows\System32\advapi32.dll`:                          700000 + rand.Intn(100000),
		`C:\Windows\System32\gdi32.dll`:                             300000 + rand.Intn(100000),
		`C:\Windows\System32\msvcrt.dll`:                            800000 + rand.Intn(100000),
		`C:\Windows\System32\ws2_32.dll`:                            400000 + rand.Intn(50000),
		`C:\Windows\System32\ole32.dll`:                             1300000 + rand.Intn(200000),
		`C:\Windows\System32\shell32.dll`:                           21000000 + rand.Intn(2000000),
		`C:\Windows\System32\comctl32.dll`:                          600000 + rand.Intn(100000),
		`C:\Windows\System32\crypt32.dll`:                           1600000 + rand.Intn(200000),
		`C:\Windows\System32\secur32.dll`:                           50000 + rand.Intn(20000),
		`C:\Windows\System32\winhttp.dll`:                           900000 + rand.Intn(100000),
		`C:\Windows\System32\cmd.exe`:                               300000 + rand.Intn(50000),
		`C:\Windows\System32\conhost.exe`:                           800000 + rand.Intn(100000),
		`C:\Windows\System32\taskmgr.exe`:                           1200000 + rand.Intn(200000),
		`C:\Windows\System32\notepad.exe`:                           200000 + rand.Intn(50000),
		`C:\Windows\System32\mmc.exe`:                               100000 + rand.Intn(50000),
		`C:\Windows\System32\regedit.exe`:                           400000 + rand.Intn(50000),
		`C:\Windows\System32\svchost.exe`:                           50000 + rand.Intn(20000),
		`C:\Windows\System32\lsass.exe`:                             60000 + rand.Intn(20000),
		`C:\Windows\System32\services.exe`:                          80000 + rand.Intn(20000),
		`C:\Windows\System32\csrss.exe`:                             20000 + rand.Intn(5000),
		`C:\Windows\System32\smss.exe`:                              150000 + rand.Intn(50000),
		`C:\Windows\System32\wininit.exe`:                           50000 + rand.Intn(20000),
		`C:\Windows\System32\winlogon.exe`:                          700000 + rand.Intn(100000),
		`C:\Windows\System32\dwm.exe`:                               100000 + rand.Intn(50000),
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`: 500000 + rand.Intn(100000),
	}
	for path, size := range dlls {
		writeFileWithSizeWin(s, path, size)
	}

	// ─── User desktop/documents ──────────────────────────────────────
	writeFile(s, fmt.Sprintf(`C:\Users\%s\Desktop\passwords.txt`, user),
		fmt.Sprintf(`Credentials - INTERNAL USE ONLY
================================
Server: %s
Admin: admin / P@ssw0rd123!
Database: sa / Str0ngDBP@ss#2024
VPN: %s / Welcome1!
WiFi: CorpNet / C0rp0r@teWifi!
`, s.Hostname, user))

	writeFile(s, fmt.Sprintf(`C:\Users\%s\Desktop\ReadMe.txt`, user), `Welcome to your new workstation.

Please contact IT Support for any issues:
  Email: helpdesk@corp.local
  Phone: x4357 (HELP)

Standard software has been pre-installed.
Your profile will sync within 24 hours.
`)

	writeFile(s, fmt.Sprintf(`C:\Users\%s\Documents\Meeting Notes.txt`, user),
		fmt.Sprintf(`Q1 2024 Planning Meeting - %s
============================
Attendees: IT, Security, DevOps
- Migrate remaining workloads to Azure
- Renew SSL certificates by end of month
- Security audit scheduled for next quarter
- Budget approved for new monitoring tools
Action Items:
  %s: Update firewall rules
  admin: Review access policies
`, now.Add(-time.Duration(rand.Intn(30))*24*time.Hour).Format("2006-01-02"), user))

	writeFile(s, fmt.Sprintf(`C:\Users\%s\Documents\contacts.csv`, user), `Name,Email,Phone
John Smith,john.smith@corp.local,x1234
Sarah Johnson,sarah.j@corp.local,x1235
Mike Chen,m.chen@corp.local,x1236
IT Helpdesk,helpdesk@corp.local,x4357
`)

	writeFile(s, fmt.Sprintf(`C:\Users\%s\Documents\budget_2024.xlsx`, user), "PK\x03\x04") // xlsx magic bytes

	// ─── Downloads ───────────────────────────────────────────────────
	writeFileWithSizeWin(s, fmt.Sprintf(`C:\Users\%s\Downloads\setup.exe`, user), 5000000+rand.Intn(10000000))
	writeFileWithSizeWin(s, fmt.Sprintf(`C:\Users\%s\Downloads\report.pdf`, user), 200000+rand.Intn(500000))
	writeFileWithSizeWin(s, fmt.Sprintf(`C:\Users\%s\Downloads\TeamViewer_Setup.exe`, user), 30000000+rand.Intn(10000000))

	// ─── Recent items ────────────────────────────────────────────────
	recentItems := []string{"passwords.txt.lnk", "Meeting Notes.txt.lnk", "report.pdf.lnk", "budget_2024.xlsx.lnk"}
	for _, item := range recentItems {
		writeFile(s, fmt.Sprintf(`C:\Users\%s\AppData\Roaming\Microsoft\Windows\Recent\%s`, user, item), "")
	}

	// ─── Chrome profile ──────────────────────────────────────────────
	writeFile(s, fmt.Sprintf(`C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default\Preferences`, user),
		`{"profile":{"name":"Person 1"},"browser":{"enabled_labs_experiments":[]}}`)
	writeFile(s, fmt.Sprintf(`C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default\Bookmarks`, user), `{
  "roots": {
    "bookmark_bar": {
      "children": [
        {"name": "Gmail", "url": "https://mail.google.com"},
        {"name": "Jira", "url": "https://jira.corp.local"},
        {"name": "Confluence", "url": "https://wiki.corp.local"}
      ]
    }
  }
}`)

	// ─── Program files ───────────────────────────────────────────────
	writeFileWithSizeWin(s, `C:\Program Files\Google\Chrome\Application\chrome.exe`, 2800000+rand.Intn(500000))
	writeFile(s, `C:\Program Files\Google\Chrome\Application\120.0.6099.130\chrome.dll`, "")
	writeFileWithSizeWin(s, `C:\Program Files\7-Zip\7z.exe`, 500000+rand.Intn(100000))
	writeFileWithSizeWin(s, `C:\Program Files\Windows Defender\MsMpEng.exe`, 150000+rand.Intn(50000))
	writeFile(s, `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`, "")
	writeFile(s, `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE`, "")
	writeFile(s, `C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE`, "")

	// ─── Temp files ──────────────────────────────────────────────────
	for i := 0; i < 5+rand.Intn(10); i++ {
		name := fmt.Sprintf("tmp%s.tmp", randomAlphaNum(8))
		writeFileWithSizeWin(s, fmt.Sprintf(`C:\Users\%s\AppData\Local\Temp\%s`, user, name), rand.Intn(100000))
	}

	// ─── Prefetch ────────────────────────────────────────────────────
	prefetchApps := []string{"CMD.EXE", "CHROME.EXE", "SVCHOST.EXE", "POWERSHELL.EXE",
		"EXPLORER.EXE", "NOTEPAD.EXE", "TASKMGR.EXE", "OUTLOOK.EXE"}
	for _, app := range prefetchApps {
		name := fmt.Sprintf("%s-%s.pf", app, randomAlphaNum(8))
		writeFileWithSizeWin(s, `C:\Windows\Prefetch\`+name, 30000+rand.Intn(50000))
	}

	// ─── Event log ───────────────────────────────────────────────────
	writeFile(s, `C:\Windows\Logs\CBS\CBS.log`, fmt.Sprintf(`%s, Info                  CBS    Loaded Servicing Stack v10.0.19041.3636
%s, Info                  CBS    Session: 30885003_4294967295 initialized.
%s, Info                  CBS    Perf: EvaluateApplicability took 97ms for package Update~31bf3856ad364e35~amd64~~10.0.1.0
`,
		now.Add(-24*time.Hour).Format("2006-01-02 15:04:05"),
		now.Add(-23*time.Hour).Format("2006-01-02 15:04:05"),
		now.Add(-22*time.Hour).Format("2006-01-02 15:04:05")))

	// ─── inetpub ─────────────────────────────────────────────────────
	writeFile(s, `C:\inetpub\wwwroot\iisstart.htm`, `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN">
<html><head><title>IIS Windows Server</title></head>
<body><h1>Internet Information Services</h1></body></html>`)
}

func writeFileWithSizeWin(s *SessionFS, path string, size int) {
	header := []byte("MZ\x90\x00\x03\x00\x00\x00") // PE header magic
	data := make([]byte, size)
	copy(data, header)
	afero.WriteFile(s.Fs, path, data, 0755)
}
