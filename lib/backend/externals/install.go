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

package externals

import (
	"context"

	"github.com/sirupsen/logrus"

	hcinstall "github.com/hashicorp/hc-install"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/hc-install/src"

	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/versions"
	"github.com/CS-SI/SafeScale/v22/lib/global"
)

func installTerraform() (string, error) {
	installer := hcinstall.NewInstaller()
	release := &releases.ExactVersion{
		Product:    product.Terraform,
		Version:    versions.Terraformv1_2_6,
		InstallDir: global.Settings.Folders.ShareDir + "/terraform/bin",
	}
	logrus.Infof("installing terraform release %s", versions.Terraformv1_2_6)
	return installer.Install(context.Background(), []src.Installable{release})
}

func installConsul() (string, error) {
	installer := hcinstall.NewInstaller()
	release := &releases.ExactVersion{
		Product:    product.Consul,
		Version:    versions.Consulv1_13_1,
		InstallDir: global.Settings.Folders.ShareDir + "/consul/bin",
	}
	logrus.Infof("installing consul release %s", versions.Consulv1_13_1)
	return installer.Install(context.Background(), []src.Installable{release})
}
