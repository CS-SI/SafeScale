/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package operations

import (
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func gatewayFromHost(task concurrency.Task, host resources.Host) (resources.Host, error) {
	if task == nil {
		return nil, fail.InvalidParameterReport("task", "cannot be nil")
	}
	if host == nil {
		return nil, fail.InvalidParameterReport("host", "cannot be nil")
	}

	network, err := host.GetDefaultNetwork(task)
	if err != nil {
		return nil, err
	}

	gw, err := network.GetGateway(task, true)
	if err == nil {
		_, err = gw.WaitSSHReady(task, temporal.GetConnectSSHTimeout())
	}

	if err != nil {
		gw, err = network.GetGateway(task, false)
		if err == nil {
			_, err = gw.WaitSSHReady(task, temporal.GetConnectSSHTimeout())
		}
	}

	if err != nil {
		return nil, fail.NotAvailableReport("no gateway available")
	}
	return gw, nil
}
