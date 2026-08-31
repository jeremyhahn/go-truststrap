// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
)

// ErrConfigRead is returned when a configuration file is present but cannot be
// opened or parsed. A file the operator named explicitly and that does not
// exist is also a read failure: silently ignoring it would start the server on
// values the operator never chose.
var ErrConfigRead = errors.New("config: read failed")

const (
	// envPrefix is the product-level environment variable prefix. A key is
	// settable as TRUSTSTRAP_<PATH>, the path uppercased with each level
	// separator replaced by an underscore, so serve.listen is
	// TRUSTSTRAP_SERVE_LISTEN.
	envPrefix = "TRUSTSTRAP"

	// configName is the base name, without extension, of the configuration
	// file searched for when no explicit path is supplied.
	configName = "truststrap"

	// configType is the on-disk configuration format.
	configType = "yaml"

	// keyServeListen is the configuration key holding the serve listen address.
	keyServeListen = "serve.listen"
)

// configSearchPaths are the directories searched for configName when the
// operator does not name a file, in descending precedence.
var configSearchPaths = []string{".", "$HOME/.truststrap", "/etc/truststrap"}

// loadConfig builds the configuration below the flag layer: the defaults, the
// optional YAML file, and the TRUSTSTRAP_-prefixed environment, in ascending
// precedence. Flags sit above the returned viper and are applied by the caller
// under Flags().Changed(); see resolveListenAddr.
//
// configFile names a file explicitly. When it is empty, configName is searched
// for across configSearchPaths and its absence is not an error, because the
// file is optional.
func loadConfig(configFile string) (*viper.Viper, error) {
	v := viper.New()

	// Defaults layer. The value is the library's own default rather than a
	// literal, so the CLI and the server cannot drift apart.
	v.SetDefault(keyServeListen, bootstrap.DefaultListenAddr)

	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		v.SetConfigName(configName)
		v.SetConfigType(configType)
		for _, path := range configSearchPaths {
			v.AddConfigPath(path)
		}
	}

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if configFile == "" && errors.As(err, &notFound) {
			return v, nil
		}
		return nil, fmt.Errorf("%w: %w", ErrConfigRead, err)
	}

	return v, nil
}

// resolveListenAddr applies the documented precedence -- flag, then
// environment, then file, then default -- to the listen address. The viper
// instance already resolves the lower three layers; flagChanged is what places
// the flag above them, and it is the only correct test, because a flag left
// unset is indistinguishable from one set to its default value.
func resolveListenAddr(flagValue string, flagChanged bool, v *viper.Viper) string {
	if flagChanged {
		return flagValue
	}
	return v.GetString(keyServeListen)
}
