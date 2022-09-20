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

package ovhtf

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/terraformer"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	imageResourceSnippetPath = "snippets/resource_image.tf.template"
)

type (
	imageResource struct {
		terraformer.ResourceCore
	}
)

func newImageResource(name string) terraformer.Resource {
	out := &imageResource{terraformer.NewResourceCore(name, imageResourceSnippetPath)}
	return out
}

// ToMap returns a map of imageResource field to be used where needed
func (nr *imageResource) ToMap() map[string]any {
	return map[string]any{
		"Name": nr.Name(),
	}
}

// ListImages overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (p *provider) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError()
	// return p.Stack.(providers.StackReservedForProviderUse).ListImages(ctx, all)
}

func (p *provider) InspectImage(ctx context.Context, id string) (*abstract.Image, fail.Error) {
	// TODO implement me
	panic("implement me")
}
