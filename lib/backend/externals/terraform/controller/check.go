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

	hcinstall "github.com/hashicorp/hc-install"
	"github.com/hashicorp/hc-install/fs"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/hc-install/src"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/versions"
	"github.com/CS-SI/SafeScale/v22/lib/global"
)

func Check() error {
	installer := hcinstall.NewInstaller()
	source := &fs.AnyVersion{
		ExactBinPath: global.Settings.Folders.ShareDir + "/terraform/bin/terraform",
	}
	execPath, err := installer.Ensure(context.Background(), []src.Source{source})
	if err != nil {
		execPath, err = install()
		if err != nil {
			logrus.Fatalf("error installing terraform release '%s': %s", versions.Terraformv1_2_6, err)
		}
	} else {
		tf, err := tfexec.NewTerraform(global.Settings.Folders.TmpDir, execPath)
		if err != nil {
			logrus.Fatalf("error creating terraform exec instance: %s", err)
		}

		version, _, err := tf.Version(context.Background(), true)
		if err != nil {
			logrus.Fatalf("error checking terraform release '%s': %s", versions.Terraformv1_2_6, err)
		}

		if !version.Equal(versions.Terraformv1_2_6) {
			execPath, err = install()
			if err != nil {
				logrus.Fatalf("error installing terraform release '%s': %s", versions.Terraformv1_2_6, err)
			}
		}
	}

	global.Settings.Backend.Terraform.ExecPath = execPath
	return nil
}

func install() (string, error) {
	installer := hcinstall.NewInstaller()
	release := &releases.ExactVersion{
		Product:    product.Terraform,
		Version:    versions.Terraformv1_2_6,
		InstallDir: global.Settings.Folders.ShareDir + "/terraform/bin",
	}
	logrus.Infof("installing terraform release %s", versions.Terraformv1_2_6)
	return installer.Install(context.Background(), []src.Installable{release})
}
