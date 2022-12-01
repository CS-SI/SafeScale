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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package controller

import (
	"context"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"os/exec"

	"github.com/hashicorp/go-version"
	hcinstall "github.com/hashicorp/hc-install"
	"github.com/hashicorp/hc-install/fs"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/hc-install/src"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/versions"
	"github.com/CS-SI/SafeScale/v22/lib/global"
)

// Check ...
func Check() error {
	installer := hcinstall.NewInstaller()
	source := &fs.AnyVersion{
		ExactBinPath: global.Settings.Folders.ShareDir + "/consul/bin/consul",
	}
	execPath, err := installer.Ensure(context.Background(), []src.Source{source})
	if err != nil {
		execPath, err = install()
		if err != nil {
			logrus.Fatalf("error installing consul release '%s': %s", versions.Consulv1_13_1, err)
		}
	} else {
		// make sure installed version is the wanted version
		out, err := exec.Command(source.ExactBinPath, "version", "--format=json").Output()
		if err != nil {
			logrus.Fatalf("failed to check consul binary version: %v", err)
		}

		var unjsoned map[string]any
		err = json.Unmarshal(out, &unjsoned)
		if err != nil {
			logrus.Fatalf("failed to read consul binary version: %v", err)
		}

		versionString, ok := unjsoned["Version"].(string)
		if !ok {
			logrus.Fatalf("failed to read consul binary version: %v", err)
		}

		// If the version doesn't correspond to the wanted one, install the wanted one
		v := version.Must(version.NewVersion(versionString))
		if !v.Equal(versions.Consulv1_13_1) {
			execPath, err = install()
			if err != nil {
				logrus.Fatalf("failed to install consul release '%s': %s", versions.Consulv1_13_1, err)
			}
		}
	}

	global.Settings.Backend.Consul.ExecPath = execPath
	return nil
}

// install realizes consul installation
func install() (string, error) {
	installer := hcinstall.NewInstaller()
	release := &releases.ExactVersion{
		Product:    product.Consul,
		Version:    versions.Consulv1_13_1,
		InstallDir: global.Settings.Folders.ShareDir + "/consul/bin",
	}
	logrus.Infof("installing consul release %s", versions.Consulv1_13_1)
	return installer.Install(context.Background(), []src.Installable{release})
}
