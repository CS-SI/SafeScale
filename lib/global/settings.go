/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package global

import (
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/env"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const (
	defaultRootDir = "/opt/safescale"
)

type settings struct {
	Debug             bool
	Verbose           bool
	ReadConfigFile    string
	ReadConfigFileExt string
	Access            struct {
		Owner user.User
		Group user.Group
		UID   int
		GID   int
	}
	Backend struct {
		Listen           string
		Prefix           string // Would moved as Project in future, carried by gRPC message
		DefaultAuthority string // Default value to use for the HTTP/2 :authority header commonly used for routing gRPC calls through a backend gateway
		UseTls           bool   // Whether the gRPC server of the backend is serving in plaintext (false) or over TLS (true)
		Tls              struct {
			CertFile string
			KeyFile  string
			CAs      []string // Paths to PEM certificate chains used for verification of backend certificates. If empty, host CA chain will be used
			NoVerify bool     // Whether to ignore TLS verification checks (cert validity, hostname). *DO NOT USE IN PRODUCTION*.
		}
		Terraform struct {
			ExecPath      string
			StateInConsul bool
		}
		Consul struct { // Consul is used to store terraform states, and in the future SafeScale metadata
			ExecPath string // Contains the path of the internal consul binary
			Peers    []string
			Internal bool
		}
		Metadata struct {
			Method string // can be objectstorage or consul
		}
	}
	Folders struct {
		RootDir  string
		BinDir   string
		EtcDir   string
		VarDir   string
		TmpDir   string
		LogDir   string
		ShareDir string
	}
	WebUI struct {
		Listen  string
		WebRoot string
		UseTls  bool // Whether the Web server is serving in plaintext (false) or over TLS (true)
		Tls     struct {
			CertFile              string
			KeyFile               string
			BackendClientCertFile string // Path to the PEM certificate used when the backend requires client certificates for TLS.
			BackendClientKeyFile  string // Path to the PEM key used when the backend requires client certificates for TLS.
			CAs                   []string
			CertVerification      string // Controls whether a client certificate is on. Allowed values: 'none', 'verify_if_given', 'require'
		}
	}
}

var (
	Settings                settings                                               // Store global settings of the app
	ValidConfigFilenameExts = []string{"json", "js", "yaml", "yml", "toml", "tml"} // contains list of accepted extension for configuration files

	once sync.Once
)

// LoadSettings initializes Settings object
// Order of priority for values:
//  1. cli flag
//  2. env var
//  3. settings file content
//  4. default value
func LoadSettings(cmd *cobra.Command, args []string) (ferr error) {
	ferr = nil
	once.Do(func() {
		var dirname, basename string
		reader := viper.New()
		configFile, err := cmd.Flags().GetString("config")
		if err != nil {
			ferr = err
			return
		}
		if configFile != "" {
			dirname, basename = filepath.Split(configFile)
			reader.AddConfigPath(dirname)
			Settings.ReadConfigFile = configFile
			Settings.ReadConfigFileExt = filepath.Ext(configFile)
		} else {
			Settings.Folders.RootDir, ferr = cmd.Flags().GetString("root-dir")
			if ferr != nil {
				return
			}
			if Settings.Folders.RootDir == "" && env.Lookup("SAFESCALE_ROOT_DIR") {
				Settings.Folders.RootDir, _ = env.Value("SAFESCALE_ROOT_DIR")
			}
			if Settings.Folders.RootDir == "" { // nolint
				Settings.Folders.RootDir = reader.GetString("safescale.root_dir")
			}
			if Settings.Folders.RootDir == "" {
				Settings.Folders.RootDir = defaultRootDir
			}
			Settings.Folders.EtcDir, ferr = cmd.Flags().GetString("etc-dir")
			if ferr != nil {
				return
			}
			if Settings.Folders.EtcDir == "" && env.Lookup("SAFESCALE_ETC_DIR") {
				Settings.Folders.EtcDir, _ = env.Value("SAFESCALE_ETC_DIR")
			}
			if Settings.Folders.EtcDir == "" { // nolint
				Settings.Folders.EtcDir = reader.GetString("safescale.etc_dir")
			}
			if Settings.Folders.EtcDir == "" && Settings.Folders.RootDir != "" {
				Settings.Folders.EtcDir = Settings.Folders.RootDir + "/etc"
			}
			if Settings.Folders.EtcDir == "" {
				ferr = fail.NotFoundError("failed to find where the configuration is stored. Please use --config, --root-dir or --etc-dir.")
				return
			}

			reader.AddConfigPath(Settings.Folders.EtcDir)
			basename = "settings"
			Settings.ReadConfigFile = Settings.Folders.EtcDir + "/" + basename
		}
		reader.SetConfigName(basename)

		ferr = loadGlobalSettings(cmd, reader)
		if ferr != nil {
			return
		}

		ferr = loadBackendSettings(cmd, reader)
		if ferr != nil {
			return
		}

		ferr = loadWebUISettings(cmd, reader)
		if ferr != nil {
			return
		}
	})
	return ferr
}

func loadGlobalSettings(cmd *cobra.Command, reader *viper.Viper) error {
	var err error
	// --bin-dir
	Settings.Folders.BinDir, err = cmd.Flags().GetString("bin-dir")
	if err != nil {
		return err
	}

	if Settings.Folders.BinDir == "" && env.Lookup("SAFESCALE_BIN_DIR") {
		Settings.Folders.BinDir, _ = env.Value("SAFESCALE_BIN_DIR")
	}
	if Settings.Folders.BinDir == "" { // nolint
		Settings.Folders.BinDir = reader.GetString("safescale.bin_dir")
	}
	if Settings.Folders.BinDir == "" {
		Settings.Folders.BinDir = Settings.Folders.RootDir + "/bin"
	}

	// --var-dir
	Settings.Folders.VarDir, err = cmd.Flags().GetString("var-dir")
	if err != nil {
		return err
	}

	if Settings.Folders.VarDir == "" && env.Lookup("SAFESCALE_VAR_DIR") {
		Settings.Folders.VarDir, _ = env.Value("SAFESCALE_VAR_DIR")
	}
	if Settings.Folders.VarDir == "" { // nolint
		Settings.Folders.VarDir = reader.GetString("safescale.var_dir")
	}
	if Settings.Folders.VarDir == "" {
		Settings.Folders.VarDir = Settings.Folders.RootDir + "/var"
	}

	// --tmp-dir
	Settings.Folders.TmpDir, err = cmd.Flags().GetString("tmp-dir")
	if err != nil {
		return err
	}

	if Settings.Folders.TmpDir == "" && env.Lookup("SAFESCALE_TMP_DIR") {
		Settings.Folders.TmpDir, _ = env.Value("SAFESCALE_TMP_DIR")
	}
	if Settings.Folders.TmpDir == "" { // nolint
		Settings.Folders.EtcDir = reader.GetString("safescale.tmp_dir")
	}
	if Settings.Folders.TmpDir == "" {
		Settings.Folders.TmpDir = Settings.Folders.VarDir + "/tmp"
	}

	// --log-dir
	Settings.Folders.LogDir, err = cmd.Flags().GetString("log-dir")
	if err != nil {
		return err
	}

	if Settings.Folders.LogDir == "" && env.Lookup("SAFESCALE_LOG_DIR") {
		Settings.Folders.LogDir, _ = env.Value("SAFESCALE_LOG_DIR")
	}
	if Settings.Folders.LogDir == "" { // nolint
		Settings.Folders.LogDir = reader.GetString("safescale.log_dir")
	}
	if Settings.Folders.LogDir == "" {
		Settings.Folders.LogDir = Settings.Folders.VarDir + "/log"
	}

	// settings.Folders.ShareDir = reader.GetString("safescale.share_dir")
	// if settings.Folders.ShareDir == "" {
	Settings.Folders.ShareDir = Settings.Folders.VarDir + "/share"
	// }

	// --owner
	owner, err := cmd.Flags().GetString("owner")
	if err != nil {
		return err
	}

	if owner == "" { // nolint
		owner, _ = env.Value("SAFESCALE_OWNER")
	}
	if owner == "" { // nolint
		owner = reader.GetString("safescale.owner")
	}
	if owner == "" { // nolint
		owner = "safescale"
	}
	ownerObject, err := user.Lookup(owner)
	if err != nil {
		switch err.(type) {
		case user.UnknownUserError:
			return fail.NotAvailableError("owner '%s' not found. Either create it, or set wanted value in settings", owner)
		default:
			return fail.Wrap(err)
		}
	}

	Settings.Access.Owner = *ownerObject
	Settings.Access.UID, err = strconv.Atoi(ownerObject.Uid)
	if err != nil {
		return fail.Wrap(err)
	}

	// --group
	group, err := cmd.Flags().GetString("group")
	if err != nil {
		return err
	}

	if group == "" { // nolint
		group, _ = env.Value("SAFESCALE_GROUP")
	}
	if group == "" { // nolint
		group = reader.GetString("safescale.group")
	}
	if group == "" {
		group = "safescale"
	}
	groupObject, err := user.LookupGroup(group)
	if err != nil {
		switch err.(type) {
		case user.UnknownGroupError:
			return fail.NotAvailableError("group '%s' not found. Either create it, or set wanted value in settings", group)
		default:
			return fail.Wrap(err)
		}
	}

	Settings.Access.Group = *groupObject
	Settings.Access.GID, err = strconv.Atoi(groupObject.Gid)
	if err != nil {
		return fail.Wrap(err)
	}

	// --debug
	Settings.Debug, err = cmd.Flags().GetBool("debug")
	if err != nil && reader.IsSet("safescale.debug") {
		Settings.Debug = reader.GetBool("safescale.debug")
	}

	Settings.Verbose, err = cmd.Flags().GetBool("verbose")
	if err != nil && reader.IsSet("safescale.verbose") {
		Settings.Verbose = reader.GetBool("safescale.verbose")
	}

	return nil
}

const defaultBackendPort = "50051"

func loadBackendSettings(cmd *cobra.Command, reader *viper.Viper) error {
	var err error
	// FIXME: add validation of backend format (<host|ip>:<port>)
	if cmd.Name() == "backend" {
		Settings.Backend.Listen, err = cmd.Flags().GetString("listen")
		if err != nil {
			return err
		}
	}
	if Settings.Backend.Listen == "" { // nolint
		Settings.Backend.Listen, _, _ = env.FirstValue("SAFESCALE_DAEMON_LISTEN", "SAFESCALE_BACKEND_LISTEN")
	}
	if Settings.Backend.Listen == "" { // nolint
		Settings.Backend.Listen = reader.GetString("safescale.backend.listen")
	}
	if Settings.Backend.Listen == "" {
		Settings.Backend.Listen = ":" + defaultBackendPort
	}

	Settings.Backend.UseTls = false
	Settings.Backend.UseTls, err = cmd.Flags().GetBool("backend-use-tls")
	if err != nil {
		Settings.Backend.UseTls, err = cmd.Flags().GetBool("daemon-use-tls")
		if err != nil {
			value, _, ok := env.FirstValue("SAFESCALE_DAEMON_USE_TLS", "SAFESCALE_BACKEND_USE_TLS")
			if ok {
				Settings.Backend.UseTls = translateStringToBool(value, true)
			} else if reader.IsSet("safescale.backend.use_tls") {
				Settings.Backend.UseTls = reader.GetBool("safescale.backen.use_tls")
			}
		}
	}

	Settings.Backend.Tls.NoVerify = true
	value, err := cmd.Flags().GetBool("backend-tls-noverify")
	if err != nil {
		value, _, ok := env.FirstValue("SAFESCALE_BACKEND_TLS_NOVERIFY", "SAFESCALE_DAEMON_TLS_NOVERIFY")
		if ok {
			Settings.Backend.Tls.NoVerify = translateStringToBool(value, true)
		} else if reader.IsSet("safescale.backend.tls.noverify") {
			Settings.Backend.Tls.NoVerify = reader.GetBool("safescale.backend.tls.noverify")
		}
	} else {
		Settings.Backend.Tls.NoVerify = value
	}

	// Settings.Backend.DefaultAuthority, err = cmd.Flags().GetString("backend-default-authority")
	// if err != nil {
	// 	return err
	// }
	if Settings.Backend.DefaultAuthority == "" {
		Settings.Backend.DefaultAuthority, _, _ = env.FirstValue("SAFESCALE_BACKEND_DEFAULT_AUTHORITY", "SAFESCALE_DAEMON_DEFAULT_AUTHORITY")
	}
	if Settings.Backend.DefaultAuthority == "" && reader.IsSet("safescale.backend.tls.default_authority") {
		Settings.Backend.DefaultAuthority = reader.GetString("safescale.backend.tls.default_authority")
	}

	// Settings.Backend.Tls.CAs, err = cmd.Flags().GetStringSlice("backend-tls-ca-files")
	// if err != nil {
	// 	return err
	// }
	if len(Settings.Backend.Tls.CAs) == 0 && env.Lookup("SAFESCALE_BACKEND_TLS_CA_FILES") {
		value, _ := env.Value("SAFESCALE_BACKEND_TLS_CA_FILES")
		list := strings.Split(value, ",")
		if len(list) > 0 {
			Settings.Backend.Tls.CAs = list
		}
	}
	if len(Settings.Backend.Tls.CAs) == 0 && reader.IsSet("safescale.backend.tls.ca_files") {
		Settings.Backend.Tls.CAs = reader.GetStringSlice("safescale.backend.tls.ca_files")
	}

	return nil
}

const defaultWebUIPort = "50080"

func loadWebUISettings(cmd *cobra.Command, reader *viper.Viper) error {
	elder, xerr := cli.ElderOfCommand(cmd)
	if xerr != nil {
		return xerr
	}

	if elder.Name() != WebUICmdLabel {
		return nil
	}

	var err error
	// FIXME: add validation of listen format (<host|ip>:<port>)
	Settings.WebUI.Listen, err = cmd.Flags().GetString("listen")
	if err != nil {
		return err
	}
	if Settings.WebUI.Listen == "" && env.Lookup("SAFESCALE_WEBUI_LISTEN") {
		Settings.WebUI.Listen, _ = env.Value("SAFESCALE_WEBUI_LISTEN")
	}
	if Settings.WebUI.Listen == "" { // nolint
		Settings.WebUI.Listen = reader.GetString("safescale.webui.listen")
	}
	if Settings.WebUI.Listen == "" {
		Settings.WebUI.Listen = ":" + defaultWebUIPort
	}

	if Settings.Backend.Listen == "" {
		Settings.Backend.Listen, err = cmd.Flags().GetString("backend")
		if err != nil {
			return err
		}
		if Settings.Backend.Listen == "" && env.Lookup("SAFESCALE_WEBUI_BACKEND") {
			Settings.Backend.Listen, _ = env.Value("SAFESCALE_WEBUI_BACKEND")
		}
		if Settings.Backend.Listen == "" {
			Settings.WebUI.Listen = ":" + defaultBackendPort
		}
	}

	// Settings.WebUI.Tls.BackendClientCertFile, err = cmd.Flags().GetString("backend-client-cert-file")
	// if err != nil {
	// 	return err
	// }
	if Settings.WebUI.Tls.BackendClientCertFile == "" { // nolint
		Settings.WebUI.Tls.BackendClientCertFile, _ = env.Value("SAFESCALE_WEBUI_TLS_BACKEND_CLIENT_CERT_FILE")
	}
	if Settings.WebUI.Tls.BackendClientCertFile == "" { // nolint
		Settings.WebUI.Tls.BackendClientCertFile = reader.GetString("safescale.webui.tls.backend_client_cert_file")
	}

	// Settings.WebUI.Tls.BackendClientKeyFile, err = cmd.Flags().GetString("backend-client-key-file")
	// if err != nil {
	// 	return err
	// }
	if Settings.WebUI.Tls.BackendClientKeyFile == "" { // nolint
		Settings.WebUI.Tls.BackendClientKeyFile, _ = env.Value("SAFESCALE_WEBUI_TLS_BACKEND_CLIENT_KEY_FILE")
	}
	if Settings.WebUI.Tls.BackendClientKeyFile == "" { // nolint
		Settings.WebUI.Tls.BackendClientKeyFile = reader.GetString("safescale.webui.tls.backend_client_key_file")
	}

	if Settings.WebUI.Tls.BackendClientCertFile != "" || Settings.WebUI.Tls.BackendClientKeyFile != "" {
		if Settings.WebUI.Tls.BackendClientCertFile == "" {
			return fail.NewError("flag 'safescale.webui.tls.backend_client_cert_file' must be set when 'safescale.webui.tls.backend_client_key_file' is set")
		}

		if Settings.WebUI.Tls.BackendClientKeyFile == "" {
			return fail.NewError("flag 'safescale.webui.tls_backend_client_key_file' must be set when 'safescale.webui.tls.backend_client_cert_file' is set")
		}
	}

	Settings.WebUI.WebRoot, err = cmd.Flags().GetString("webroot")
	if err != nil {
		return err
	}
	if Settings.WebUI.WebRoot == "" && env.Lookup("SAFESCALE_WEBUI_WEBROOT") {
		Settings.WebUI.WebRoot, _ = env.Value("SAFESCALE_WEBUI_WEBROOT")
	}
	if Settings.WebUI.Listen == "" { // nolint
		Settings.WebUI.Listen = reader.GetString("safescale.webui.webroot")
	}

	return nil
}

// BuildFolderTree builds the folder tree needed by SafeScale daemon to work correctly
func BuildFolderTree() error {
	dirList := []struct {
		path   string
		rights os.FileMode
	}{
		{Settings.Folders.RootDir, 0750},
		// {settings.Folders.EtcDir, 0750},
		{Settings.Folders.VarDir, 0770},
		{Settings.Folders.TmpDir, 0770},
		{Settings.Folders.LogDir, 0770},
		{Settings.Folders.ShareDir + "/terraform/bin", 0700}, // used terraform binary will be stored here
	}

	for _, v := range dirList {
		xerr := mkdir(v.path, v.rights, Settings.Access.UID, Settings.Access.GID)
		if xerr != nil {
			return xerr
		}
	}

	e, err := os.Executable()
	if err != nil {
		return fail.Wrap(err, "failed to get path of binary")
	}
	if Settings.Folders.BinDir != "" && path.Dir(e) != Settings.Folders.BinDir {
		fmt.Printf("For consistency, you should move safescale binary in '%s'\n", Settings.Folders.BinDir)
	}

	return nil
}

// mkdir creates a folder with appropriate ownership
func mkdir(path string, rights os.FileMode, uid, gid int) fail.Error {
	state, err := os.Stat(path)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			err = os.MkdirAll(path, rights)
			if err != nil {
				return fail.Wrap(err, "failed to create folder '%s'", path)
			}

			err := os.Chown(path, uid, gid)
			if err != nil {
				return fail.Wrap(err)
			}
			state, err = os.Stat(path)
			if err != nil {
				return fail.Wrap(err)
			}

		default:
			return fail.Wrap(err)
		}
	}
	if !state.IsDir() {
		return fail.NotAvailableError("'%s' exists but is not a folder", path)
	}

	return nil
}

// translateStringToBool translates a string value to a bool value
func translateStringToBool(in string, emptyAsTrue bool) bool {
	switch strings.ToLower(in) {
	case "true", "yes", "ok", "1":
		return true
	case "":
		return emptyAsTrue
	default:
		return false
	}
}
