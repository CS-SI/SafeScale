/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package cluster

import (
	"github.com/CS-SI/SafeScale/deploy/cluster/api"
)

type BluePrintParameters map[string]interface{}

type BluePrint struct {
	instance api.Cluster

	InstallGateway   func(BluePrintParameters) error
	ConfigureGateway func(BluePrintParameters) error
	CreateMasters    func(BluePrintParameters) error
	CreateNodes      func(bool, BluePrintParameters) error
	ConfigureMasters func(BluePrintParameters) error
	ConfigureNodes   func(bool, BluePrintParameters) error
	ConfigureCluster func(BluePrintParameters) error
}

/*
// Build constructs the infrastructure wanted
func (bp *BluePrint) Build(request api.Request) (api.Cluster, error) {
	var mastersChannel chan error
	var mastersStatus error
	var gatewayChannem chan error
	var gatewayStatus error
	var privnodesChannel chan error
	var privnodesStatus error
	var pubnodesChannel chan error
	var pubnodesStatus error

	if bp.Destroy == nil {
		log.Println("Warning: Destroy func undefined in Blueprint, will not be able to cleanup on failure.")
	}

	//bp.createNetwork()
	if bp.InstallGateway != nil {
		err := bp.ConfigureGateway()
		if err != nil {
			if bp.Destroy != nil {
				bp.Destroy()
			}
		}
	}
	if bp.CreateMasters != nil {
		go func(done chan error) {
		}()
	}
	if bp.CreateMasters != nil {
		bp.CreateMasters()
	}
	if bp.CreateNodes != nil {
		bp.CreateMasters()
	}
	if bp.ConfigureGateway != nil {
		bp.ConfigureGateway()
	}
}
*/
