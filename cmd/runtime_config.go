package cmd

import (
	"fmt"
	"math"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type runtimeConfig struct {
	shutdownDelay   time.Duration
	shutdownTimeout time.Duration
	connectTimeout  time.Duration
	reloadInterval  time.Duration
}

func defaultRuntimeConfig() runtimeConfig {
	return runtimeConfig{5 * time.Second, 25 * time.Second, 10 * time.Second, 30 * time.Second}
}

func addRuntimeFlags(flags *pflag.FlagSet) {
	c := defaultRuntimeConfig()
	flags.Duration("shutdown-delay", c.shutdownDelay, "Routing propagation delay before closing listeners during shutdown")
	flags.Duration("shutdown-timeout", c.shutdownTimeout, "Shared request and tunnel drain budget after shutdown-delay")
	flags.Duration("upstream-connect-timeout", c.connectTimeout, "Control-protocol establishment timeout (dial, TLS handshake, request write, and response headers)")
	flags.Duration("cert-reload-interval", c.reloadInterval, "Poll interval for externally supplied TLS certificates")
}

func readRuntimeConfig(settings *viper.Viper) (runtimeConfig, error) {
	c := defaultRuntimeConfig()
	for _, setting := range []struct {
		name string
		dest *time.Duration
		zero bool
	}{
		{"shutdown-delay", &c.shutdownDelay, true},
		{"shutdown-timeout", &c.shutdownTimeout, false},
		{"upstream-connect-timeout", &c.connectTimeout, false},
		{"cert-reload-interval", &c.reloadInterval, false},
	} {
		if settings.IsSet(setting.name) {
			value, err := time.ParseDuration(settings.GetString(setting.name))
			if err != nil {
				return c, fmt.Errorf("invalid %s: %w", setting.name, err)
			}
			*setting.dest = value
		}
		if *setting.dest < 0 || (!setting.zero && *setting.dest == 0) {
			return c, fmt.Errorf("invalid %s: duration must be positive (only shutdown-delay allows zero)", setting.name)
		}
	}
	if c.shutdownDelay > time.Duration(math.MaxInt64)-c.shutdownTimeout {
		return c, fmt.Errorf("shutdown-delay plus shutdown-timeout overflows a duration")
	}
	return c, nil
}
