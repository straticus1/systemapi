package main

import (
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
)

type SoftwareMetrics struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture,omitempty"`
}

func gatherSoftware() []SoftwareMetrics {
	var software []SoftwareMetrics

	switch runtime.GOOS {
	case "linux":
		software = gatherSoftwareLinux()
	case "darwin":
		software = gatherSoftwareDarwin()
	case "windows":
		software = gatherSoftwareWindows()
	}

	return software
}

func gatherSoftwareLinux() []SoftwareMetrics {
	var software []SoftwareMetrics
	
	// Try dpkg first (Debian/Ubuntu)
	cmd := exec.Command("dpkg-query", "-W", "-f=${Package}||${Version}||${Architecture}\\n")
	out, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			parts := strings.Split(line, "||")
			if len(parts) >= 2 && parts[0] != "" {
				arch := ""
				if len(parts) >= 3 {
					arch = parts[2]
				}
				software = append(software, SoftwareMetrics{
					Name:         strings.TrimSpace(parts[0]),
					Version:      strings.TrimSpace(parts[1]),
					Architecture: strings.TrimSpace(arch),
				})
			}
		}
		return software
	}

	// Try rpm next (RHEL/CentOS)
	cmd2 := exec.Command("rpm", "-qa", "--qf", "%{NAME}||%{VERSION}||%{ARCH}\\n")
	out2, err2 := cmd2.Output()
	if err2 == nil {
		lines := strings.Split(string(out2), "\n")
		for _, line := range lines {
			parts := strings.Split(line, "||")
			if len(parts) >= 2 && parts[0] != "" {
				arch := ""
				if len(parts) >= 3 {
					arch = parts[2]
				}
				software = append(software, SoftwareMetrics{
					Name:         strings.TrimSpace(parts[0]),
					Version:      strings.TrimSpace(parts[1]),
					Architecture: strings.TrimSpace(arch),
				})
			}
		}
	}

	return software
}

func gatherSoftwareDarwin() []SoftwareMetrics {
	var software []SoftwareMetrics
	
	// Use system_profiler
	cmd := exec.Command("system_profiler", "SPApplicationsDataType", "-json")
	out, err := cmd.Output()
	if err != nil {
		return software
	}

	var data struct {
		SPApplicationsDataType []struct {
			Name    string `json:"_name"`
			Version string `json:"version"`
		} `json:"SPApplicationsDataType"`
	}

	if err := json.Unmarshal(out, &data); err != nil {
		return software
	}

	for _, app := range data.SPApplicationsDataType {
		if app.Name != "" && app.Version != "" {
			software = append(software, SoftwareMetrics{
				Name:    app.Name,
				Version: app.Version,
			})
		}
	}
	
	return software
}

func gatherSoftwareWindows() []SoftwareMetrics {
	var software []SoftwareMetrics
	
	// Use PowerShell to read Uninstall keys
	psCommand := `Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion | Where-Object { $_.DisplayName -ne $null } | ConvertTo-Json -Compress`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCommand)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return software
	}

    // Windows sometimes returns an object or an array depending on if one or many matches occur
    // ConvertTo-Json behavior quirk. So we fall back to generic unmarshal.
	var apps []struct {
		DisplayName    string `json:"DisplayName"`
		DisplayVersion string `json:"DisplayVersion"`
	}

	if err := json.Unmarshal(out, &apps); err != nil {
        var app struct {
            DisplayName    string `json:"DisplayName"`
            DisplayVersion string `json:"DisplayVersion"`
        }
        if err2 := json.Unmarshal(out, &app); err2 == nil {
            software = append(software, SoftwareMetrics{
                Name:    app.DisplayName,
                Version: app.DisplayVersion,
            })
        }
		return software
	}

	for _, app := range apps {
		software = append(software, SoftwareMetrics{
			Name:    app.DisplayName,
			Version: app.DisplayVersion,
		})
	}
	
	return software
}
