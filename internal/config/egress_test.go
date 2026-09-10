package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goodtune/ghp/internal/egress"
)

func TestEgressYAMLAndEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := `egress:
  strategy: weighted_round_robin
  proxies:
    - name: a
      url: http://proxy-a:3128
      weight: 3
    - name: b
      url: https://proxy-b:3128
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHP_EGRESS_STRATEGY", egress.LeastConnections)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Egress.Strategy != egress.LeastConnections || len(cfg.Egress.Proxies) != 2 || cfg.Egress.Proxies[0].Weight == nil || *cfg.Egress.Proxies[0].Weight != 3 || cfg.Egress.Proxies[1].Weight != nil {
		t.Fatalf("incorrect egress configuration: %+v", cfg.Egress)
	}
	if err := os.WriteFile(path, []byte("egress:\n  proxies:\n    - name: a\n      url: http://proxy\n      weight: 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("explicit zero weight should fail")
	}
}

func TestEgressRequiresRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("egress:\n  proxies:\n    - name: new\n      url: http://new-proxy\nadmins: [alice]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	cfg.Egress = egress.Config{Proxies: []egress.Proxy{{Name: "old", URL: "http://old-proxy"}}}
	if err := cfg.ReloadFrom(path); err != nil {
		t.Fatal(err)
	}
	if cfg.Egress.Proxies[0].Name != "old" || !cfg.IsAdmin("alice") {
		t.Fatal("reload changed infrastructure or failed to apply runtime settings")
	}
}
