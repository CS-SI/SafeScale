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

package app

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/appwide/env"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const defaultRootDir = "/opt/safescale"

type settings struct {
	Debug   bool
	Verbose bool
	Access  struct {
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
			ExecPath string
		}
	}
	Folders struct {
		RootDir  string
		EtcDir   string
		VarDir   string
		TmpDir   string
		LogDir   string
		ShareDir string
	}
	WebUI struct {
		Listen string
		UseTls bool // Whether the Web server is serving in plaintext (false) or over TLS (true)
		Tls    struct {
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
	Config settings

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
		configFile, err := cmd.Flags().GetString("conf")
		if err != nil {
			rootDir, err := cmd.Flags().GetString("root-dir")
			if err != nil {
				ferr = fail.NotFoundError("failed to find SafeScale root dir. Please provide configuration file (--conf) or root dir (--rootdir)")
				return
			}

			reader.AddConfigPath(rootDir + "/etc")
		} else {
			dirname, basename = filepath.Split(configFile)
			reader.AddConfigPath(dirname)
		}
		if basename == "" {
			basename = "settings"
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
	Config.Folders.RootDir, err = cmd.Flags().GetString("root-dir")
	if err != nil {
		return err
	}

	if Config.Folders.RootDir == "" && env.Lookup("SAFESCALE_ROOT_DIR") {
		Config.Folders.RootDir, _ = env.Value("SAFESCALE_ROOT_DIR")
	}
	if Config.Folders.RootDir == "" {
		Config.Folders.RootDir = reader.GetString("safescale.root_dir")
	}
	if Config.Folders.RootDir == "" {
		Config.Folders.RootDir = defaultRootDir
	}

	Config.Folders.EtcDir, err = cmd.Flags().GetString("etc-dir")
	if err != nil {
		return err
	}

	if Config.Folders.EtcDir == "" && env.Lookup("SAFESCALE_ETC_DIR") {
		Config.Folders.EtcDir, _ = env.Value("SAFESCALE_ETC_DIR")
	}
	if Config.Folders.EtcDir == "" { // nolint
		Config.Folders.EtcDir = reader.GetString("safescale.etc_dir")
	}
	if Config.Folders.EtcDir == "" {
		Config.Folders.EtcDir = Config.Folders.RootDir + "/etc"
	}

	// --var-dir
	Config.Folders.VarDir, err = cmd.Flags().GetString("var-dir")
	if err != nil {
		return err
	}

	if Config.Folders.VarDir == "" && env.Lookup("SAFESCALE_VAR_DIR") {
		Config.Folders.VarDir, _ = env.Value("SAFESCALE_VAR_DIR")
	}
	if Config.Folders.VarDir == "" { // nolint
		Config.Folders.VarDir = reader.GetString("safescale.var_dir")
	}
	if Config.Folders.VarDir == "" {
		Config.Folders.VarDir = Config.Folders.RootDir + "/var"
	}

	// --tmp-dir
	Config.Folders.TmpDir, err = cmd.Flags().GetString("tmp-dir")
	if err != nil {
		return err
	}

	if Config.Folders.TmpDir == "" && env.Lookup("SAFESCALE_TMP_DIR") {
		Config.Folders.TmpDir, _ = env.Value("SAFESCALE_TMP_DIR")
	}
	if Config.Folders.TmpDir == "" { // nolint
		Config.Folders.EtcDir = reader.GetString("safescale.tmp_dir")
	}
	if Config.Folders.TmpDir == "" {
		Config.Folders.TmpDir = Config.Folders.VarDir + "/tmp"
	}

	// --log-dir
	Config.Folders.LogDir, err = cmd.Flags().GetString("log-dir")
	if err != nil {
		return err
	}

	if Config.Folders.LogDir == "" && env.Lookup("SAFESCALE_LOG_DIR") {
		Config.Folders.LogDir, _ = env.Value("SAFESCALE_LOG_DIR")
	}
	if Config.Folders.LogDir == "" { // nolint
		Config.Folders.LogDir = reader.GetString("safescale.log_dir")
	}
	if Config.Folders.LogDir == "" {
		Config.Folders.LogDir = Config.Folders.VarDir + "/log"
	}

	// settings.Folders.ShareDir = reader.GetString("safescale.share_dir")
	// if settings.Folders.ShareDir == "" {
	Config.Folders.ShareDir = Config.Folders.VarDir + "/share"
	// }

	// --owner
	owner, err := cmd.Flags().GetString("owner")
	if err != nil {
		return err
	}

	if owner == "" {
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

	Config.Access.Owner = *ownerObject
	Config.Access.UID, err = strconv.Atoi(ownerObject.Uid)
	if err != nil {
		return fail.Wrap(err)
	}

	// --group
	group, err := cmd.Flags().GetString("group")
	if err != nil {
		return err
	}

	if group == "" {
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

	Config.Access.Group = *groupObject
	Config.Access.GID, err = strconv.Atoi(groupObject.Gid)
	if err != nil {
		return fail.Wrap(err)
	}

	// --debug
	Config.Debug, err = cmd.Flags().GetBool("debug")
	if err != nil && reader.IsSet("safescale.debug") {
		Config.Debug = reader.GetBool("safescale.debug")
	}

	Config.Verbose, err = cmd.Flags().GetBool("verbose")
	if err != nil && reader.IsSet("safescale.verbose") {
		Config.Verbose = reader.GetBool("safescale.verbose")
	}

	return nil
}

const defaultBackendPort = "50051"

func loadBackendSettings(cmd *cobra.Command, reader *viper.Viper) error {
	var err error
	// FIXME: add validation of backend format (<host|ip>:<port>)
	Config.Backend.Listen, err = cmd.Flags().GetString("backend")
	if err != nil {
		return err
	}

	if Config.Backend.Listen == "" && cmd.Name() == "backend" {
		Config.Backend.Listen, err = cmd.Flags().GetString("listen")
		if err != nil {
			return err
		}
	}
	if Config.Backend.Listen == "" { // nolint
		Config.Backend.Listen, _, _ = env.FirstValue("SAFESCALE_DAEMON_LISTEN", "SAFESCALE_BACKEND_LISTEN")
	}
	if Config.Backend.Listen == "" { // nolint
		Config.Backend.Listen = reader.GetString("safescale.backend.listen")
	}
	if Config.Backend.Listen == "" {
		Config.Backend.Listen = ":" + defaultBackendPort
	}

	Config.Backend.UseTls = false
	Config.Backend.UseTls, err = cmd.Flags().GetBool("backend-use-tls")
	if err != nil {
		Config.Backend.UseTls, err = cmd.Flags().GetBool("daemon-use-tls")
		if err != nil {
			value, _, ok := env.FirstValue("SAFESCALE_DAEMON_USE_TLS", "SAFESCALE_BACKEND_USE_TLS")
			if ok {
				Config.Backend.UseTls = translateStringToBool(value, true)
			} else if reader.IsSet("safescale.backend.use_tls") {
				Config.Backend.UseTls = reader.GetBool("safescale.backen.use_tls")
			}
		}
	}

	Config.Backend.Tls.NoVerify = true
	value, err := cmd.Flags().GetBool("backend-tls-noverify")
	if err != nil {
		value, _, ok := env.FirstValue("SAFESCALE_BACKEND_TLS_NOVERIFY", "SAFESCALE_DAEMON_TLS_NOVERIFY")
		if ok {
			Config.Backend.Tls.NoVerify = translateStringToBool(value, true)
		} else if reader.IsSet("safescale.backend.tls.noverify") {
			Config.Backend.Tls.NoVerify = reader.GetBool("safescale.backend.tls.noverify")
		}
	} else {
		Config.Backend.Tls.NoVerify = value
	}

	Config.Backend.DefaultAuthority, err = cmd.Flags().GetString("backend-default-authority")
	if err != nil {
		return err
	}
	if Config.Backend.DefaultAuthority == "" {
		Config.Backend.DefaultAuthority, _, _ = env.FirstValue("SAFESCALE_BACKEND_DEFAULT_AUTHORITY", "SAFESCALE_DAEMON_DEFAULT_AUTHORITY")
	}
	if Config.Backend.DefaultAuthority == "" && reader.IsSet("safescale.backend.tls.default_authority") {
		Config.Backend.DefaultAuthority = reader.GetString("safescale.backend.tls.default_authority")
	}

	Config.Backend.Tls.CAs, err = cmd.Flags().GetStringSlice("backend-tls-ca-files")
	if err != nil {
		return err
	}
	if len(Config.Backend.Tls.CAs) == 0 && env.Lookup("SAFESCALE_BACKEND_TLS_CA_FILES") {
		value, _ := env.Value("SAFESCALE_BACKEND_TLS_CA_FILES")
		list := strings.Split(value, ",")
		if len(list) > 0 {
			Config.Backend.Tls.CAs = list
		}
	}
	if len(Config.Backend.Tls.CAs) == 0 && reader.IsSet("safescale.backend.tls.ca_files") {
		Config.Backend.Tls.CAs = reader.GetStringSlice("safescale.backend.tls.ca_files")
	}

	return nil
}

const defaultWebUIPort = "50080"

func loadWebUISettings(cmd *cobra.Command, reader *viper.Viper) error {
	var err error
	// FIXME: add validation of listen format (<host|ip>:<port>)
	if cmd.Name() == "webui" {
		Config.WebUI.Listen, err = cmd.Flags().GetString("listen")
		if err != nil {
			return err
		}
		if Config.WebUI.Listen == "" && env.Lookup("SAFESCALE_WEBUI_LISTEN") {
			Config.WebUI.Listen, _ = env.Value("SAFESCALE_WEBUI_LISTEN")
		}
		if Config.WebUI.Listen == "" { // nolint
			Config.WebUI.Listen = reader.GetString("safescale.webui.listen")
		}
		if Config.WebUI.Listen == "" {
			Config.WebUI.Listen = ":" + defaultWebUIPort
		}
	}

	Config.WebUI.Tls.BackendClientCertFile, err = cmd.Flags().GetString("backend-client-cert-file")
	if err != nil {
		return err
	}
	if Config.WebUI.Tls.BackendClientCertFile == "" { // nolint
		Config.WebUI.Tls.BackendClientCertFile, _ = env.Value("SAFESCALE_WEBUI_TLS_BACKEND_CLIENT_CERT_FILE")
	}
	if Config.WebUI.Tls.BackendClientCertFile == "" { // nolint
		Config.WebUI.Tls.BackendClientCertFile = reader.GetString("safescale.webui.tls.backend_client_cert_file")
	}

	Config.WebUI.Tls.BackendClientKeyFile, err = cmd.Flags().GetString("backend-client-key-file")
	if err != nil {
		return err
	}
	if Config.WebUI.Tls.BackendClientKeyFile == "" { // nolint
		Config.WebUI.Tls.BackendClientKeyFile, _ = env.Value("SAFESCALE_WEBUI_TLS_BACKEND_CLIENT_KEY_FILE")
	}
	if Config.WebUI.Tls.BackendClientKeyFile == "" { // nolint
		Config.WebUI.Tls.BackendClientKeyFile = reader.GetString("safescale.webui.tls.backend_client_key_file")
	}

	if Config.WebUI.Tls.BackendClientCertFile != "" || Config.WebUI.Tls.BackendClientKeyFile != "" {
		if Config.WebUI.Tls.BackendClientCertFile == "" {
			return fail.NewError("flag 'safescale.webui.tls.backend_client_cert_file' must be set when 'safescale.webui.tls.backend_client_key_file' is set")
		}

		if Config.WebUI.Tls.BackendClientKeyFile == "" {
			return fail.NewError("flag 'safescale.webui.tls_backend_client_key_file' must be set when 'safescale.webui.tls.backend_client_cert_file' is set")
		}
	}

	return nil
}

// BuildFolderTree builds the folder tree needed by SafeScale daemon to work correctly
func BuildFolderTree() {
	dirList := []struct {
		path   string
		rights os.FileMode
	}{
		{Config.Folders.RootDir, 0750},
		// {settings.Folders.EtcDir, 0750},
		{Config.Folders.VarDir, 0770},
		{Config.Folders.TmpDir, 0770},
		{Config.Folders.LogDir, 0770},
		{Config.Folders.ShareDir + "/terraform/bin", 0700}, // used terraform binary will be stored here
	}

	for _, v := range dirList {
		xerr := mkdir(v.path, v.rights, Config.Access.UID, Config.Access.GID)
		if xerr != nil {
			logrus.Fatal(xerr.Error())
		}
	}

	// e, err := os.Executable()
	// if err != nil {
	// 	return fail.Wrap(err, "failed to get path of binary")
	// }
	// if path.Dir(e) != settings.Folders.binDir {
	// 	fmt.Printf("Remember to move safescale binary in '%s'\n", settings.Folders.binDir)
	// }
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
