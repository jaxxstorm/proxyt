package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func TestLoadConfiguration(t *testing.T) {
	t.Run("loads explicit yaml file", func(t *testing.T) {
		settings, _ := newTestSettings(t)
		configFile := writeTestConfig(t, "domain: config.example.com\nhttp-only: true\nport: \"8080\"\n")

		if err := loadConfiguration(settings, configFile, os.UserHomeDir); err != nil {
			t.Fatalf("load configuration: %v", err)
		}
		if got := settings.GetString("domain"); got != "config.example.com" {
			t.Fatalf("domain = %q, want config.example.com", got)
		}
		if !settings.GetBool("http-only") {
			t.Fatal("http-only = false, want true")
		}
		if got := settings.GetString("port"); got != "8080" {
			t.Fatalf("port = %q, want 8080", got)
		}
	})

	t.Run("loads default yaml file", func(t *testing.T) {
		settings, _ := newTestSettings(t)
		home := t.TempDir()
		configFile := filepath.Join(home, ".proxyt.yaml")
		if err := os.WriteFile(configFile, []byte("domain: default.example.com\nhttp-only: true\n"), 0o600); err != nil {
			t.Fatalf("write default config: %v", err)
		}

		if err := loadConfiguration(settings, "", func() (string, error) { return home, nil }); err != nil {
			t.Fatalf("load default configuration: %v", err)
		}
		if got := settings.GetString("domain"); got != "default.example.com" {
			t.Fatalf("domain = %q, want default.example.com", got)
		}
	})

	t.Run("allows missing default yaml file", func(t *testing.T) {
		settings, _ := newTestSettings(t)
		if err := loadConfiguration(settings, "", func() (string, error) { return t.TempDir(), nil }); err != nil {
			t.Fatalf("load missing default configuration: %v", err)
		}
	})

	t.Run("rejects missing explicit yaml file", func(t *testing.T) {
		settings, _ := newTestSettings(t)
		err := loadConfiguration(settings, filepath.Join(t.TempDir(), "missing.yaml"), os.UserHomeDir)
		if err == nil {
			t.Fatal("expected missing explicit configuration error")
		}
	})

	t.Run("rejects invalid yaml file", func(t *testing.T) {
		settings, _ := newTestSettings(t)
		configFile := writeTestConfig(t, "domain: [\n")
		if err := loadConfiguration(settings, configFile, os.UserHomeDir); err == nil {
			t.Fatal("expected invalid YAML error")
		}
	})
}

func TestConfigurationPrecedence(t *testing.T) {
	settings, flags := newTestSettings(t)
	configFile := writeTestConfig(t, "domain: config.example.com\nhttp-only: true\n")
	if err := loadConfiguration(settings, configFile, os.UserHomeDir); err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	t.Setenv("PROXYT_DOMAIN", "environment.example.com")
	if got := settings.GetString("domain"); got != "environment.example.com" {
		t.Fatalf("environment domain = %q, want environment.example.com", got)
	}
	if err := flags.Set("domain", "flag.example.com"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	if got := settings.GetString("domain"); got != "flag.example.com" {
		t.Fatalf("flag domain = %q, want flag.example.com", got)
	}
}

func TestValidateServeConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		values  map[string]any
		wantErr bool
	}{
		{name: "missing domain", values: map[string]any{"http-only": true}, wantErr: true},
		{name: "missing certificate directory", values: map[string]any{"domain": "proxy.example.com", "issue": false}, wantErr: true},
		{name: "missing lets encrypt email", values: map[string]any{"domain": "proxy.example.com", "cert-dir": "/certs", "issue": true}, wantErr: true},
		{name: "http only", values: map[string]any{"domain": "proxy.example.com", "http-only": true}, wantErr: false},
		{name: "manual certificate", values: map[string]any{"domain": "proxy.example.com", "cert-dir": "/certs", "issue": false}, wantErr: false},
		{name: "lets encrypt", values: map[string]any{"domain": "proxy.example.com", "cert-dir": "/certs", "issue": true, "email": "admin@example.com"}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings, _ := newTestSettings(t)
			for key, value := range tt.values {
				settings.Set(key, value)
			}

			err := validateServeConfiguration(settings)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateServeConfiguration() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func newTestSettings(t *testing.T) (*viper.Viper, *pflag.FlagSet) {
	t.Helper()

	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.String("domain", "", "")
	flags.String("port", "80", "")
	flags.String("https-port", "443", "")
	flags.String("email", "", "")
	flags.String("cert-dir", "", "")
	flags.Bool("issue", true, "")
	flags.Bool("debug", false, "")
	flags.Bool("http-only", false, "")
	flags.String("bind", "0.0.0.0", "")
	addRuntimeFlags(flags)

	settings := viper.New()
	configureServeSettings(settings, flags)
	return settings, flags
}

func writeTestConfig(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "proxyt.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	return path
}

func TestRuntimeConfiguration(t *testing.T) {
	s, _ := newTestSettings(t)
	c, err := readRuntimeConfig(s)
	if err != nil || c != defaultRuntimeConfig() {
		t.Fatalf("defaults = %+v, %v", c, err)
	}
	for _, key := range []string{"shutdown-delay", "shutdown-timeout", "upstream-connect-timeout", "cert-reload-interval"} {
		t.Run(key, func(t *testing.T) {
			s, flags := newTestSettings(t)
			s.SetConfigType("yaml")
			if err := s.ReadConfig(strings.NewReader(key + ": 3s\n")); err != nil {
				t.Fatal(err)
			}
			check := func(want time.Duration) {
				t.Helper()
				c, err := readRuntimeConfig(s)
				if err != nil {
					t.Fatal(err)
				}
				got := map[string]time.Duration{"shutdown-delay": c.shutdownDelay, "shutdown-timeout": c.shutdownTimeout, "upstream-connect-timeout": c.connectTimeout, "cert-reload-interval": c.reloadInterval}[key]
				if got != want {
					t.Fatalf("%s = %v, want %v", key, got, want)
				}
			}
			check(3 * time.Second)
			t.Setenv("PROXYT_"+strings.ToUpper(strings.ReplaceAll(key, "-", "_")), "2s")
			check(2 * time.Second)
			if err := flags.Set(key, "1s"); err != nil {
				t.Fatal(err)
			}
			check(time.Second)
		})
	}
	for _, mode := range []string{"http", "manual", "acme"} {
		for _, key := range []string{"shutdown-delay", "shutdown-timeout", "upstream-connect-timeout", "cert-reload-interval"} {
			for _, value := range []string{"garbage", "999999999999999999999h", "-1s", "0s"} {
				t.Run(mode+"/"+key+"/"+value, func(t *testing.T) {
					s, _ := newTestSettings(t)
					s.Set("domain", "proxy.example.com")
					s.Set("http-only", mode == "http")
					s.Set("issue", mode == "acme")
					s.Set("email", "a@example.com")
					s.Set("cert-dir", "certs")
					s.Set(key, value)
					err := validateServeConfiguration(s)
					if key == "shutdown-delay" && value == "0s" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil || !strings.Contains(err.Error(), key) {
						t.Fatalf("expected %s error, got %v", key, err)
					}
				})
			}
		}
	}
	s, _ = newTestSettings(t)
	s.Set("shutdown-delay", "9223372036854775807ns")
	if _, err := readRuntimeConfig(s); err == nil {
		t.Fatal("accepted shutdown duration overflow")
	}
}
