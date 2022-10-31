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

package options

import (
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type Options interface {
	Load(key string) (any, fail.Error)
	Store(key string, value any) (any, fail.Error)
}

type options struct {
	m sync.Map
}

func New() *options {
	return &options{}
}

// Load returns the value of key in options
func (o *options) Load(key string) (any, fail.Error) {
	if valid.IsNull(o) {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	out, ok := o.m.Load(key)
	if !ok {
		return nil, fail.NotFoundError("failed to find key '%s' in options", key)
	}

	return out, nil
}

// Store sets the value of key in options
func (o *options) Store(key string, value any) (any, fail.Error) {
	if valid.IsNull(o) {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	o.m.Store(key, value)
	return value, nil
}
