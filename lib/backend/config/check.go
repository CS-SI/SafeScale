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

package config

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	hcinstall "github.com/hashicorp/hc-install"
	"github.com/hashicorp/hc-install/fs"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/src"
	"github.com/hashicorp/terraform-exec/tfexec"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/env"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

var (
	terraformv1_2_6 = version.Must(version.NewVersion("1.2.6"))
	consulv1_13_1   = version.Must(version.NewVersion("1.13.1"))
)

// Check makes sure configuration is ok
// logrus.Fatal is called if not to stop the program
func Check(cmd *cobra.Command) (suffix string, ferr error) {
	logrus.Infoln("Checking configuration")
	_, xerr := iaas.GetTenantNames()
	if xerr != nil {
		return "", xerr
	}

	// DEV VAR
	suffix = ""
	// if suffixCandidate := os.Getenv("SAFESCALE_METADATA_SUFFIX"); suffixCandidate != "" {
	suffixCandidate, ok := env.Value("SAFESCALE_METADATA_SUFFIX")
	if ok && suffixCandidate != "" {
		suffix = suffixCandidate
	}

	safescaleEnv, err := env.Keys(env.OptionStartsWithAny("SAFESCALE"))
	if err != nil {
		return "", fail.Wrap(err)
	}
	for _, v := range safescaleEnv {
		value, _ := env.Value(v)
		logrus.Infof("Using %s=%s ", v, value)
	}

	err = checkTerraform()
	if err != nil {
		return "", fail.Wrap(err)
	}

	err = checkConsul()
	if err != nil {
		return "", fail.Wrap(err)
	}

	return suffix, nil
}

func checkTerraform() error {
	installer := hcinstall.NewInstaller()
	source := &fs.AnyVersion{
		ExactBinPath: global.Config.Folders.ShareDir + "/terraform/bin/terraform",
	}
	execPath, err := installer.Ensure(context.Background(), []src.Source{source})
	if err != nil {
		execPath, err = installTerraform()
		if err != nil {
			logrus.Fatalf("error installing terraform release '%s': %s", terraformv1_2_6, err)
		}
	} else {
		tf, err := tfexec.NewTerraform(global.Config.Folders.TmpDir, execPath)
		if err != nil {
			logrus.Fatalf("error creating terraform exec instance: %s", err)
		}
		version, _, err := tf.Version(context.Background(), true)
		if err != nil {
			logrus.Fatalf("error checking terraform release '%s': %s", terraformv1_2_6, err)
		}
		if !version.Equal(terraformv1_2_6) {
			execPath, err = installTerraform()
			if err != nil {
				logrus.Fatalf("error installing terraform release '%s': %s", terraformv1_2_6, err)
			}
		}
	}

	global.Config.Backend.Terraform.ExecPath = execPath
	// workingDir := settings.Folders.ShareDir+"/terraform/bin"
	// tf, err := tfexec.NewTerraform(workingDir, execPath)
	// if err != nil {
	// 	logrus.Fatalf("error running NewTerraform: %s", err)
	// }
	//
	// err = tf.Init(context.Background(), tfexec.Upgrade(true))
	// if err != nil {
	// 	logrus.Fatalf("error running Init: %s", err)
	// }
	//
	// state, err := tf.Show(context.Background())
	// if err != nil {
	// 	logrus.Fatalf("error running Show: %s", err)
	// }
	//
	// fmt.Println(state.FormatVersion) // "0.1"
	return nil
}

func checkConsul() error {
	installer := hcinstall.NewInstaller()
	source := &fs.AnyVersion{
		Product:      &product.Consul,
		ExactBinPath: global.Config.Folders.ShareDir + "/consul/bin/consul",
	}
	execPath, err := installer.Ensure(context.Background(), []src.Source{source})
	if err != nil {
		execPath, err = installConsul()
		if err != nil {
			logrus.Fatalf("error installing terraform release '%s': %s", terraformv1_2_6, err)
		}
	} else {
		tf, err := tfexec.NewTerraform(global.Config.Folders.TmpDir, execPath)
		if err != nil {
			logrus.Fatalf("error creating terraform exec instance: %s", err)
		}
		version, _, err := tf.Version(context.Background(), true)
		if err != nil {
			logrus.Fatalf("error checking terraform release '%s': %s", terraformv1_2_6, err)
		}
		if !version.Equal(terraformv1_2_6) {
			execPath, err = installTerraform()
			if err != nil {
				logrus.Fatalf("error installing terraform release '%s': %s", terraformv1_2_6, err)
			}
		}
	}

	global.Config.Backend.Consul.ExecPath = execPath
	// workingDir := settings.Folders.ShareDir+"/terraform/bin"
	// tf, err := tfexec.NewTerraform(workingDir, execPath)
	// if err != nil {
	// 	logrus.Fatalf("error running NewTerraform: %s", err)
	// }
	//
	// err = tf.Init(context.Background(), tfexec.Upgrade(true))
	// if err != nil {
	// 	logrus.Fatalf("error running Init: %s", err)
	// }
	//
	// state, err := tf.Show(context.Background())
	// if err != nil {
	// 	logrus.Fatalf("error running Show: %s", err)
	// }
	//
	// fmt.Println(state.FormatVersion) // "0.1"
	return nil
}
