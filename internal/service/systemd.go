package service

import (
	"bytes"
	"strings"
	"text/template"
)

// unitTemplate is the systemd unit. The sandbox options leave the service able to read
// its configuration and the file roots, write only its state and logs, and do nothing
// else: no new privileges, no devices, no kernel tunables, a native system call filter.
const unitTemplate = `[Unit]
Description={{.Description}}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={{.User}}
Group={{.User}}
ExecStart={{.ExecStart}}
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
{{- if .BindPrivileged}}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
{{- else}}
CapabilityBoundingSet=
AmbientCapabilities=
{{- end}}
{{- range .ReadWrite}}
ReadWritePaths={{.}}
{{- end}}
{{- range .ReadOnly}}
ReadOnlyPaths=-{{.}}
{{- end}}
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`

// Unit renders the systemd unit of a spec.
func Unit(s Spec) (string, error) {
	user := s.Account
	if user == "" {
		user = "privasimu-bridge"
	}
	exec := []string{s.Executable, "--config", s.ConfigPath, s.Mode}
	for i, a := range exec {
		exec[i] = systemdQuote(a)
	}
	data := struct {
		Description, User, ExecStart string
		BindPrivileged               bool
		ReadWrite, ReadOnly          []string
	}{s.Description(), user, strings.Join(exec, " "), s.BindPrivileged, s.ReadWritePaths, s.ReadOnlyPaths}
	t := template.Must(template.New("unit").Parse(unitTemplate))
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// systemdQuote quotes a word of ExecStart when it holds spaces or special characters.
func systemdQuote(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\"'\\$%;") {
		return a
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", "$$", "%", "%%")
	return `"` + r.Replace(a) + `"`
}
