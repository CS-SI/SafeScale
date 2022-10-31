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

	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api/terraformer"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// Core represents a virtual network
type (
	Option func(*Core) fail.Error

	Core struct {
		Name string                   `json:"name"` // name of the abstract resource
		Tags data.Map[string, string] `json:"tags,omitempty"`

		snippet  string
		summoner terraformerapi.Summoner
	}
)

// NewCore initializes a new instance of Network
func NewCore(name string, options ...Option) (*Core, fail.Error) {
	c := &Core{
		Name: name,
		Tags: data.NewMap[string, string](),
	}
	c.Tags["CreationDate"] = time.Now().Format(time.RFC3339)
	c.Tags["ManagedBy"] = "safescale"

	for _, v := range options {
		if v != nil {
			xerr := v(c)
			if xerr != nil {
				return nil, xerr
			}
		}
	}
	return c, nil
}

// UseTerraformSnippet allows to attach a snippet to the abstract resource
func UseTerraformSnippet(snippet string) Option {
	return func(c *Core) fail.Error {
		if snippet == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("snippet")
		}
		c.snippet = snippet
		return nil
	}
}

// UseSummoner ...
func UseSummoner(summoner terraformerapi.Summoner) Option {
	return func(c *Core) fail.Error {
		if summoner == nil {
			return fail.InvalidParameterCannotBeNilError("summoner")
		}
		c.summoner = summoner
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

	nc, xerr := NewCore(c.Name)
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

// Snippet returns the path of the snippet used by terraform to handle the resource
func (c Core) Snippet() string {
	return c.snippet
}

// Summoner returns the summoner to use to realize the resource in terraform
func (c Core) Summoner() terraformerapi.Summoner {
	return c.summoner
}
