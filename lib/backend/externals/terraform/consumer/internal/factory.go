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

package internal

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	iaasoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	uuidpkg "github.com/gofrs/uuid"
	"github.com/hashicorp/terraform-exec/tfexec"
)

// New instantiates a terraform file builder that will put file in 'workDir'
func New(provider ProviderUsingTerraform, opts options.Options) (api.Terraformer, fail.Error) {
	if valid.IsNull(provider) {
		return nil, fail.InvalidInstanceError()
	}

	out := &renderer{
		provider: provider,
		opts:     provider.TerraformerOptions(),
		mu:       &sync.Mutex{},
	}

	var xerr fail.Error
	out.config, xerr = options.Value[api.Configuration](opts, iaasoptions.BuildOptionTerraformerConfiguration)
	if xerr != nil {
		return nil, xerr
	}

	out.scope, xerr = options.Value[api.ScopeLimitedToTerraformerUse](opts, iaasoptions.OptionScope)
	if xerr != nil {
		return nil, xerr
	}

	// out.workdir, xerr = options.HolderOf[string](opts, ConfigOptionWorkDir)
	// if xerr != nil {
	// 	return nil, xerr
	// }
	if out.config.WorkDir == "" {
		return nil, fail.InvalidRequestError("workdir cannot be empty string; please add 'UseWorkDir()'")
	}

	if out.config.ExecPath == "" {
		return nil, fail.InvalidRequestError("execpath cannot be empty string; please add 'WithExecPath()'")
	}

	if out.config.PluginDir == "" {
		return nil, fail.InvalidRequestError("plugindir cannot be empty string; please add 'WithPluginDir()'")
	}

	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return nil, fail.Wrap(err, "failed to generate uuid")
	}

	out.buildPath = filepath.Join(out.config.WorkDir, uuid.String())
	err = os.MkdirAll(out.buildPath, 0700)
	if err != nil {
		return nil, fail.Wrap(err, "failed to create temporary folder")
	}

	out.executor, err = tfexec.NewTerraform(out.buildPath, out.config.ExecPath)
	if err != nil {
		return nil, fail.Wrap(err, "failed to instantiate terraform executor")
	}

	out.env = out.defaultEnv()
	return out, nil
}
