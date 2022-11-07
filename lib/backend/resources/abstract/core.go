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

	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// Core represents a virtual network
type (
	Option func(*Core) fail.Error

	Core struct {
		Name string                   `json:"name"` // name of the abstract resource
		Tags data.Map[string, string] `json:"tags,omitempty"`

		scope            ScopeLimitedToAbstractUse
		terraformSnippet string
		terraformData    []byte
		useTerraform     bool
	}

	ScopeLimitedToAbstractUse interface {
		Resource(kind string, ref string) (clonable.Clonable, fail.Error)
		AllResources() ([]terraformerapi.Resource, fail.Error)
	}
)

const (
	Unnamed = "unnamed"
)

// New initializes a new instance of Network
func New(opts ...Option) (*Core, fail.Error) {
	c := &Core{
		Name: Unnamed,
		Tags: data.NewMap[string, string](),
	}
	c.Tags["CreationDate"] = time.Now().Format(time.RFC3339)
	c.Tags["ManagedBy"] = "safescale"

	for _, v := range opts {
		if v != nil {
			xerr := v(c)
			if xerr != nil {
				return nil, xerr
			}
		}
	}
	return c, nil
}

// WithName defines the name of the resource (otherwise will be set to "unnamed")
func WithName(name string) Option {
	return func(c *Core) fail.Error {
		if name == "" {
			c.Name = Unnamed
		} else {
			c.Name = name
		}
		return nil
	}
}

// UseTerraformSnippet allows to attach a snippet to the abstract resource
func UseTerraformSnippet(snippet string) Option {
	return func(c *Core) fail.Error {
		if snippet == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("snippet")
		}

		c.terraformSnippet = snippet
		c.useTerraform = true
		return nil
	}
}

// IsNull ...
// satisfies interface clonable.Clonable
func (c *Core) IsNull() bool {
	return c == nil || len(c.Tags) == 0
}

// Clone ...
// satisfies interface clonable.Clonable
func (c *Core) Clone() (clonable.Clonable, error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}

	nc, xerr := New(WithName(c.Name))
	if xerr != nil {
		return nil, xerr
	}

	return nc, nc.Replace(c)
}

// Replace ...
// satisfies interface clonable.Clonable
func (c *Core) Replace(p clonable.Clonable) error {
	if c == nil {
		return fail.InvalidInstanceError()
	}
	if p == nil {
		return fail.InvalidParameterCannotBeNilError("p")
	}

	src, err := lang.Cast[*Core](p)
	if err != nil {
		return err
	}

	*c = *src
	return nil
}

// TerraformSnippet returns the name of the terraform Snippet used to define resource
func (c *Core) TerraformSnippet() string {
	if valid.IsNull(c) {
		return ""
	}

	return c.terraformSnippet
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

// AllResources returns the scope
func (c *Core) AllResources() ([]terraformerapi.Resource, fail.Error) {
	if valid.IsNull(c) {
		return nil, fail.InvalidInstanceError()
	}

	return c.scope.AllResources()
}
