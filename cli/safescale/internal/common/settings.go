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

package common

import (
	"fmt"
	"os"
	"os/user"
	"strconv"

	"github.com/spf13/viper"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/lib/utils/app/env"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type Settings struct {
	Access struct {
		Owner user.User
		UID   int
		Group user.Group
		GID   int
	}
	Folders struct {
		rootDir string
		etcDir  string
		// binDir string
		varDir   string
		tmpDir   string
		shareDir string
	}
}

// LoadSettings initializes Settings object
// Order of read:
//  1. cli flag
//  2. env var
//  3. settings file content
//  4. default value
func LoadSettings(configFile string, rootDir string, c *cli.Context) (settings Settings, ferr error) {
	reader := viper.New()
	if configFile != "" {
		reader.AddConfigPath(configFile)
	}
	if rootDir != "" {
		reader.AddConfigPath(rootDir + "/etc")
	}
	reader.SetConfigName("settings")

	settings.Folders.rootDir = c.String("root-dir")
	if settings.Folders.rootDir == "" && env.Lookup("SAFESCALE_ROOT_DIR") {
		settings.Folders.rootDir, _ = env.Value("SAFESCALE_ROOT_DIR")
	}
	if settings.Folders.rootDir == "" {
		settings.Folders.rootDir = reader.GetString("safescale.root_dir")
	}
	if settings.Folders.rootDir == "" {
		settings.Folders.rootDir = rootDir
	} else if settings.Folders.rootDir != rootDir {
		return settings, fail.InconsistentError("reading settings file from '%s' but settings file tells root_dir='%s'", rootDir+"/etc", settings.Folders.rootDir)
	}
	if settings.Folders.rootDir == "" {
		return Settings{}, fmt.Errorf("failed to determine SafeScale root dir")
	}

	settings.Folders.etcDir = c.String("etc-dir")
	if settings.Folders.etcDir == "" && env.Lookup("SAFESCALE_ETC_DIR") {
		settings.Folders.etcDir, _ = env.Value("SAFESCALE_ETC_DIR")
	}
	if settings.Folders.etcDir == "" { //nolint
		settings.Folders.etcDir = reader.GetString("safescale.etc_dir")
	}
	if settings.Folders.etcDir == "" {
		settings.Folders.etcDir = settings.Folders.rootDir + "/etc"
	}

	// settings.Folders.binDir = reader.GetString("safescale.bin_dir")
	// if settings.Folders.binDir == "" {
	// 	settings.Folders.binDir = settings.Folders.rootDir + "/bin"
	// }

	settings.Folders.varDir = reader.GetString("safescale.var_dir")
	if settings.Folders.varDir == "" {
		settings.Folders.varDir = settings.Folders.rootDir + "/var"
	}

	settings.Folders.tmpDir = c.String("tmp-dir")
	if settings.Folders.tmpDir == "" && env.Lookup("SAFESCALE_TMP_DIR") {
		settings.Folders.tmpDir, _ = env.Value("SAFESCALE_TMP_DIR")
	}
	if settings.Folders.tmpDir == "" { //nolint
		settings.Folders.etcDir = reader.GetString("safescale.tmp_dir")
	}
	if settings.Folders.tmpDir == "" {
		settings.Folders.tmpDir = settings.Folders.varDir + "/tmp"
	}

	settings.Folders.shareDir = reader.GetString("safescale.share_dir")
	if settings.Folders.shareDir == "" {
		settings.Folders.shareDir = settings.Folders.varDir + "/share"
	}

	owner := reader.GetString("safescale.user")
	if owner == "" {
		owner = "safescale"
	}
	ownerObject, err := user.Lookup(owner)
	if err != nil {
		return Settings{}, fail.Wrap(err)
	}
	settings.Access.Owner = *ownerObject
	settings.Access.UID, err = strconv.Atoi(ownerObject.Uid)
	if err != nil {
		return Settings{}, fail.Wrap(err)
	}

	group := reader.GetString("safescale.group")
	if group == "" {
		group = "safescale"
	}
	groupObject, err := user.LookupGroup(group)
	if err != nil {
		return Settings{}, fail.Wrap(err)
	}
	settings.Access.Group = *groupObject
	settings.Access.GID, err = strconv.Atoi(groupObject.Gid)
	if err != nil {
		return Settings{}, fail.Wrap(err)
	}

	return settings, nil
}

// BuildFolderTree builds the folder tree needed by SafeScale daemon to work correctly
func BuildFolderTree(settings Settings) fail.Error {
	dirList := []string{
		settings.Folders.rootDir,
		settings.Folders.etcDir,
		settings.Folders.varDir,
		settings.Folders.tmpDir,
		settings.Folders.shareDir,
	}

	for _, v := range dirList {
		xerr := mkdir(v, settings.Access.UID, settings.Access.GID)
		if xerr != nil {
			return xerr
		}
	}

	// e, err := os.Executable()
	// if err != nil {
	// 	return fail.Wrap(err,"failed to get path of binary")
	// }
	// if path.Dir(e) != settings.Folders.binDir {
	// 	fmt.Printf("Remember to move safescale binary in '%s'\n", settings.Folders.binDir)
	// }
	return nil
}

// mkdir creates a folder with appropriate ownership
func mkdir(path string, uid, gid int) fail.Error {
	state, err := os.Stat(path)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			err = os.MkdirAll(path, 0700)
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
