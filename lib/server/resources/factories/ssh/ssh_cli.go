//go:build !tunnel
// +build !tunnel

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

package share

import (
	"os"

	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/bycli"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/bylib"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// defaultSSHConnectorFactory is the default factory to create SSH Connector, based on ssh.cliconnector
func defaultSSHConnectorFactory(config sshapi.Config) (sshapi.Connector, fail.Error) {
	if choice := os.Getenv("SAFESCALE_DEFAULT_SSH"); choice != "" {
		switch choice {
		case "cli":
			return bycli.NewConnector(config)
		case "lib":
			return bylib.NewConnector(config)
		default:
			return bycli.NewConnector(config)
		}
	}

	return bycli.NewConnector(config)
}

func GetDefaultConnectorType() (string, fail.Error) {
	if choice := os.Getenv("SAFESCALE_DEFAULT_SSH"); choice != "" {
		switch choice {
		case "cli":
			return "cli", nil
		case "lib":
			return "lib", nil
		default:
			return "cli", nil
		}
	}

	return "cli", nil
}
