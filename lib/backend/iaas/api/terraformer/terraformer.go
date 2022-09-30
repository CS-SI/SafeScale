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

package terraformerapi

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/hashicorp/terraform-exec/tfexec"
)

type (
	Resource interface {
		Snippet() string
		ToMap() map[string]any
	}

	Summoner interface {
		Build(resources ...Resource) fail.Error
		Apply(ctx context.Context) (map[string]tfexec.OutputMeta, fail.Error)
		Destroy(ctx context.Context) fail.Error
		Plan(ctx context.Context) (map[string]tfexec.OutputMeta, bool, fail.Error)
	}

	RequiredProvider struct {
		Source  string
		Version string
	}

	RequiredProviders map[string]RequiredProvider

	Configuration struct {
		Release       string // contains the release of terraform wanted for the hcl file produced
		WorkDir       string
		ExecPath      string
		ConsulBackend struct {
			Path string // "/safescale/terraformstate/{{ or .CurrentOrganization "default" }}/{{ or .CurrentProject "default" }}"
			Use  bool
		}
		Scope struct { // Note: don't use job.Scope, to prevent import cycle, and avoid "outside" dependencies for iaas backend
			Organization string
			Project      string
			Tenant       string
		}
		RequiredProviders
	}
)
