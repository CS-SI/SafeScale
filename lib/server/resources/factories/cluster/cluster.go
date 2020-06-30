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

package cluster

import (
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// New creates a new instance of resources.Cluster
func New(task concurrency.Task, svc iaas.Service) (_ resources.Cluster, err error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	return operations.NewCluster(task, svc)
}

// Load loads metadata of a cluster and returns an instance of resources.Cluster
func Load(task concurrency.Task, svc iaas.Service, name string) (_ resources.Cluster, err error) {
	if task == nil {
		return nil, fail.InvalidParameterError("t", "cannot be nil")
	}
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	return operations.LoadCluster(task, svc, name)
}
