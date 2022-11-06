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

package terraformer

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const (
	TerraformStateLocal uint8 = iota
	TerraformStateRemote
)

type ResourceCore struct {
	name    string // contains the name of the resource
	snippet string // contains the snippet to use to handle the resource
	state   uint8  // tells if resource state has to be stored locally or remotely (remotely by default)
}

type ResourceOption func(rc *ResourceCore) fail.Error

// WithLocalState tells the resource will have its state saved locally
func WithLocalState() ResourceOption {
	return func(rc *ResourceCore) fail.Error {
		rc.state = TerraformStateLocal
		return nil
	}
}

// WithRemoteState tells the resource will have its state saved remotely
func WithRemoteState() ResourceOption {
	return func(rc *ResourceCore) fail.Error {
		rc.state = TerraformStateRemote
		return nil
	}
}

// NewResourceCore creates a new instance of ResourceCore
func NewResourceCore(name string, snippet string, opts ...ResourceOption) (ResourceCore, fail.Error) {
	out := ResourceCore{
		name:    name,
		snippet: snippet,
		state:   TerraformStateLocal,
	}
	for _, v := range opts {
		xerr := v(&out)
		if xerr != nil {
			return ResourceCore{}, xerr
		}
	}
	return out, nil
}

// Name returns the name of the resource
func (rc ResourceCore) Name() string {
	return rc.name
}

// Snippet returns the path of the snippet used to handle the resource
func (rc ResourceCore) ProviderData() string {
	return rc.snippet
}

// LocalState tells if the state of the resource will be saved locally
func (rc ResourceCore) LocalState() bool {
	return rc.state == TerraformStateLocal
}

// RemoteState tells if the state of the resource will be saved remotely
func (rc ResourceCore) RemoteState() bool {
	return rc.state == TerraformStateRemote
}
