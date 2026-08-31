// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
)

// envServeListen is the environment variable bound to the serve.listen key.
const envServeListen = "TRUSTSTRAP_SERVE_LISTEN"

// writeConfig writes a YAML configuration file carrying the given listen
// address and returns its path.
func writeConfig(t *testing.T, listen string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), configName+"."+configType)
	body := "serve:\n  listen: \"" + listen + "\"\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))

	return path
}

// unsetEnv removes a variable for the duration of a test and restores whatever
// the environment held before. The layered tests need the absence of a
// variable, which t.Setenv cannot express.
func unsetEnv(t *testing.T, key string) {
	t.Helper()

	original, present := os.LookupEnv(key)
	require.NoError(t, os.Unsetenv(key))

	t.Cleanup(func() {
		if present {
			require.NoError(t, os.Setenv(key, original))
			return
		}
		require.NoError(t, os.Unsetenv(key))
	})
}

// setListenFlag sets --listen the way an operator would -- through the flag
// set, so the flag is marked changed and the flag layer actually applies --
// and restores both the value and the changed bit when the test ends.
// Assigning the bound variable directly is not equivalent: an unset flag does
// not take precedence over configuration, which is the whole point of the
// Changed() test.
func setListenFlag(t *testing.T, addr string) {
	t.Helper()

	flags := serveCmd.Flags()
	original := serveListenAddr

	require.NoError(t, flags.Set(flagListen, addr))

	t.Cleanup(func() {
		require.NoError(t, flags.Set(flagListen, original))
		flags.Lookup(flagListen).Changed = false
		serveListenAddr = original
	})
}

// With no file, no environment and no flag, the address is the library's own
// default. That the CLI keeps no default of its own is the point: there is
// nothing for the server's default to drift from.
func TestResolveListenAddr_Default(t *testing.T) {
	unsetEnv(t, envServeListen)
	t.Chdir(t.TempDir())

	v, err := loadConfig("")
	require.NoError(t, err)

	assert.Equal(t, bootstrap.DefaultListenAddr, resolveListenAddr("", false, v))
}

// The file layer is above defaults.
func TestResolveListenAddr_FileOverridesDefault(t *testing.T) {
	unsetEnv(t, envServeListen)

	v, err := loadConfig(writeConfig(t, "127.0.0.1:19001"))
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:19001", resolveListenAddr("", false, v))
}

// The environment layer is above defaults when no file is present.
func TestResolveListenAddr_EnvOverridesDefault(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(envServeListen, "127.0.0.1:19002")

	v, err := loadConfig("")
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:19002", resolveListenAddr("", false, v))
}

// The environment layer is above the file layer.
func TestResolveListenAddr_EnvOverridesFile(t *testing.T) {
	t.Setenv(envServeListen, "127.0.0.1:19003")

	v, err := loadConfig(writeConfig(t, "127.0.0.1:19004"))
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:19003", resolveListenAddr("", false, v))
}

// The flag layer is above everything below it.
func TestResolveListenAddr_FlagOverridesEnvAndFile(t *testing.T) {
	t.Setenv(envServeListen, "127.0.0.1:19005")

	v, err := loadConfig(writeConfig(t, "127.0.0.1:19006"))
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:19007", resolveListenAddr("127.0.0.1:19007", true, v))
}

// A flag holding a value it was never given -- the default pflag wrote into
// the bound variable -- must not displace the environment. This is what
// Flags().Changed() buys and what BindPFlag cannot express, because a flag's
// default value is indistinguishable from the same value typed by an operator.
func TestResolveListenAddr_UnchangedFlagDoesNotOverrideEnv(t *testing.T) {
	t.Setenv(envServeListen, "127.0.0.1:19008")

	v, err := loadConfig(writeConfig(t, "127.0.0.1:19009"))
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:19008",
		resolveListenAddr(bootstrap.DefaultListenAddr, false, v))
}

// The Changed() wiring on the real command, rather than the resolver in
// isolation: an untouched flag leaves the environment in charge, and setting
// the flag puts it in charge instead.
func TestServeCmd_ListenFlagChangedPrecedence(t *testing.T) {
	t.Setenv(envServeListen, "127.0.0.1:19010")

	v, err := loadConfig(writeConfig(t, "127.0.0.1:19011"))
	require.NoError(t, err)

	flags := serveCmd.Flags()

	require.False(t, flags.Changed(flagListen))
	assert.Equal(t, "127.0.0.1:19010",
		resolveListenAddr(serveListenAddr, flags.Changed(flagListen), v))

	setListenFlag(t, "127.0.0.1:19012")

	require.True(t, flags.Changed(flagListen))
	assert.Equal(t, "127.0.0.1:19012",
		resolveListenAddr(serveListenAddr, flags.Changed(flagListen), v))
}

// The flag's own default is the library constant, so --help and the defaults
// layer state the same address.
func TestServeCmd_ListenFlagDefaultIsLibraryDefault(t *testing.T) {
	flag := serveCmd.Flags().Lookup(flagListen)
	require.NotNil(t, flag)

	assert.Equal(t, bootstrap.DefaultListenAddr, flag.DefValue)
}

// A configuration file in the working directory is found without --config.
func TestLoadConfig_SearchPathFindsWorkingDirectory(t *testing.T) {
	unsetEnv(t, envServeListen)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, configName+"."+configType),
		[]byte("serve:\n  listen: \"127.0.0.1:19013\"\n"), 0600))
	t.Chdir(dir)

	v, err := loadConfig("")
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:19013", resolveListenAddr("", false, v))
}

// A file the operator named explicitly and that is absent is a read failure,
// not a silent fall back to defaults: the operator asked for those values.
func TestLoadConfig_ExplicitFileMissing(t *testing.T) {
	_, err := loadConfig(filepath.Join(t.TempDir(), "absent.yaml"))

	assert.ErrorIs(t, err, ErrConfigRead)
}

// A file that exists but does not parse is a read failure. Tabs are not legal
// YAML indentation.
func TestLoadConfig_MalformedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), configName+"."+configType)
	require.NoError(t, os.WriteFile(path, []byte("serve:\n\tlisten: \":1\"\n"), 0600))

	_, err := loadConfig(path)

	assert.ErrorIs(t, err, ErrConfigRead)
}

// A malformed file found through the search path is a read failure too: the
// exemption is for an absent file, not for an unreadable one.
func TestLoadConfig_MalformedFileInSearchPath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, configName+"."+configType),
		[]byte("serve:\n\tlisten: \":1\"\n"), 0600))
	t.Chdir(dir)

	_, err := loadConfig("")

	assert.ErrorIs(t, err, ErrConfigRead)
}
