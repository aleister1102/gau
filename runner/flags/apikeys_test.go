package flags

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lynxsecurity/viper"
)

func TestReadConfigAPIKeysStringAndList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gau.toml")
	body := "[brave]\napikey = \"k1\"\n\n[virustotal]\napikey = [\"v1\", \"v2\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig: %v", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg, viper.DecodeHook(apiKeyDecodeHook())); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if want := []string{"k1"}; !reflect.DeepEqual(cfg.Brave.APIKeys, want) {
		t.Fatalf("brave keys = %v, want %v", cfg.Brave.APIKeys, want)
	}
	if want := []string{"v1", "v2"}; !reflect.DeepEqual(cfg.VirusTotal.APIKeys, want) {
		t.Fatalf("virustotal keys = %v, want %v", cfg.VirusTotal.APIKeys, want)
	}
}
