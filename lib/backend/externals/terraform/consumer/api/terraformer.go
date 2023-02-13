/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package api

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/hashicorp/terraform-exec/tfexec"
	tfjson "github.com/hashicorp/terraform-json"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type (
	// Terraformer exposes the methods to interact with terraform CLI
	Terraformer interface {
		Apply(ctx context.Context, def string) (map[string]tfexec.OutputMeta, fail.Error)
		Assemble(ctx context.Context, resources ...abstract.Abstract) (string, fail.Error)
		Close() fail.Error
		Destroy(ctx context.Context, def string, opts ...options.Option) fail.Error
		// Import(ctx context.Context, resourceAddress, id string) fail.Error
		Plan(ctx context.Context, def string) (map[string]tfexec.OutputMeta, bool, fail.Error)
		SetEnv(key, value string) fail.Error
		AddEnv(key, value string) fail.Error
		Reset() fail.Error
		State(ctx context.Context) (_ *tfjson.State, ferr fail.Error)
		WorkDir() (string, fail.Error)
	}

	RequiredProvider struct {
		Source  string
		Version string
	}

	RequiredProviders data.Map[string, RequiredProvider]

	// ScopeLimitedToTerraformerUse is mainly used to prevent import cycle with scopeapi
	ScopeLimitedToTerraformerUse interface {
		AllAbstracts() (map[string]abstract.Abstract, fail.Error)
		IsLoaded() bool
		LoadAbstracts(ctx context.Context) fail.Error
	}

	// Configuration carries the configuration for the Terraformer
	Configuration struct {
		Release   string // contains the release of terraform wanted for the hcl file produced
		WorkDir   string
		ExecPath  string
		PluginDir string
		Consul    struct {
			Server string
			Prefix string // should contains "safescale/terraformstate/{Scope.Organization}/{Scope.Project}/{Scope.Tenant}
		}
		Scope ScopeLimitedToTerraformerUse
		RequiredProviders
	}
)
