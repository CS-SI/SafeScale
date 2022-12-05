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

package abstract

import (
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// Core represents a virtual network
type (
	core struct {
		Name string                   `json:"name"` // name of the abstract resource
		Tags data.Map[string, string] `json:"tags,omitempty"`

		kind             string
		terraformSnippet string
		terraformTypes   []string
		extra            map[string]any
		useTerraform     bool
	}
)

const (
	Unnamed = "unnamed"

	ExtraMarkedForDestruction = "MarkedForDestruction"
)

// newCore initializes a new instance of Network
func newCore(opts ...Option) (*core, fail.Error) {
	c := &core{
		Name: Unnamed,
		Tags: data.NewMap[string, string](),
		extra: map[string]any{
			ExtraMarkedForDestruction: false,
		},
	}
	c.Tags["CreationDate"] = time.Now().Format(time.RFC3339)
	c.Tags["ManagedBy"] = "safescale"
	return c, c.AddOptions(opts...)
}

// AddOptions is used to add options on Core after creation
func (c *core) AddOptions(opts ...Option) fail.Error {
	if c == nil {
		return fail.InvalidInstanceError()
	}

	for _, v := range opts {
		if v != nil {
			xerr := v(c)
			if xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// IsNull ...
// satisfies interface clonable.Clonable
func (c *core) IsNull() bool {
	return c == nil || len(c.Tags) == 0
}

// Clone ...
// satisfies interface clonable.Clonable
func (c *core) Clone() (clonable.Clonable, error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}

	nc, xerr := newCore(WithName(c.Name))
	if xerr != nil {
		return nil, xerr
	}

	return nc, nc.Replace(c)
}

// Replace ...
// satisfies interface clonable.Clonable
func (c *core) Replace(p clonable.Clonable) error {
	if c == nil {
		return fail.InvalidInstanceError()
	}
	if p == nil {
		return fail.InvalidParameterCannotBeNilError("p")
	}

	src, err := clonable.Cast[*core](p)
	if err != nil {
		return err
	}

	*c = *src
	return nil
}

// TerraformSnippet returns the name of the terraform Snippet used to define resource
func (c *core) TerraformSnippet() string {
	if valid.IsNull(c) {
		return ""
	}

	return c.terraformSnippet
}

// TerraformTypes returns the types of the resources in terraform corresponding to the abstract
func (c *core) TerraformTypes() []string {
	if valid.IsNull(c) {
		return nil
	}

	return c.terraformTypes
}

// func (c *Core) Prepare(provider terraformer.ProviderUsingTerraform) error {
// 	if c.useTerraform {
// 		renderer, variables, xerr := provider.Renderer()
// 		if xerr != nil {
// 			return xerr
// 		}
// 		defer func() { _ = renderer.Close() }()
//
// 		// lvars.Merge(map[string]any{"Resource": r.ToMap()})
// 		variables.Merge(map[string]any{"Resource": c})
// 		content, xerr := renderer.RealizeSnippet(provider.EmbeddedFS(), c.terraformSnippet, variables)
// 		if xerr != nil {
// 			return xerr
// 		}
//
// 		c.terraformData= content
// 	}
//
// 	return nil
// }

// // AllAbstracts returns the scope
// func (c *Core) AllAbstracts(ctx context.Context) ([]terraformerapi.Resource, fail.Error) {
// 	if valid.IsNull(c) {
// 		return nil, fail.InvalidInstanceError()
// 	}
//
// 	myjob, xerr := jobapi.FromContext(ctx)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	scope, err := lang.Cast[ScopeLimitedToAbstractUse](myjob.Scope())
// 	if err != nil {
// 		return nil, fail.Wrap(err)
// 	}
//
// 	return scope.AllAbstracts()
// }

func (c *core) GetName() string {
	if valid.IsNull(c) {
		return ""
	}

	return c.Name
}

func (c *core) Kind() string {
	if valid.IsNull(c) {
		return ""
	}

	return c.kind
}

func (c *core) Extra() map[string]any {
	if valid.IsNull(c) {
		return nil
	}

	return c.extra
}