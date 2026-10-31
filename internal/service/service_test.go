package service

import (
	"strings"
	"testing"
)

func TestUnitIsHardened(t *testing.T) {
	unit, err := Unit(Spec{Name: "privasimu-bridge", Mode: "serve", Executable: "/usr/local/bin/privasimu-bridge",
		ConfigPath: "/etc/privasimu-bridge/bridge.yaml", ReadWritePaths: []string{"/var/lib/privasimu-bridge", "/var/log/privasimu-bridge"},
		ReadOnlyPaths: []string{"/srv/shares/hr"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/usr/local/bin/privasimu-bridge --config /etc/privasimu-bridge/bridge.yaml serve",
		"User=privasimu-bridge", "NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateDevices=yes",
		"MemoryDenyWriteExecute=yes", "CapabilityBoundingSet=\n", "ReadWritePaths=/var/lib/privasimu-bridge",
		"ReadOnlyPaths=-/srv/shares/hr", "UMask=0077",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	privileged, _ := Unit(Spec{Name: "b", Mode: "serve", Executable: "/opt/bridge bin/privasimu-bridge", ConfigPath: "/etc/b.yaml", BindPrivileged: true})
	if !strings.Contains(privileged, "AmbientCapabilities=CAP_NET_BIND_SERVICE") ||
		!strings.Contains(privileged, `ExecStart="/opt/bridge bin/privasimu-bridge"`) {
		t.Fatalf("%s", privileged)
	}
}

func TestSpecValidation(t *testing.T) {
	ok := Spec{Name: "privasimu-bridge", Mode: "agent", Executable: "x", ConfigPath: "y"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Spec{{Name: "a b", Mode: "serve", Executable: "x", ConfigPath: "y"}, {Name: "a", Mode: "other", Executable: "x", ConfigPath: "y"}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v must be refused", bad)
		}
	}
	if DefaultName("agent") != "privasimu-bridge-agent" || DefaultName("serve") != "privasimu-bridge" {
		t.Fatal("default names")
	}
}
