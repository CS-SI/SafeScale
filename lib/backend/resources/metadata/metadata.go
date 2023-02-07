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

package metadata

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/resources.Metadata -o mocks/mock_metadata.go

// ResourceCallback describes the function prototype to use to inspect metadata
type ResourceCallback[T abstract.Abstract] func(T, *serialize.JSONProperties) fail.Error

// AbstractCallback ...
type AbstractCallback[T abstract.Abstract] func(T) fail.Error

// PropertyCallback describes the function prototype to use to inspect metadata
type PropertyCallback[T clonable.Clonable] func(T) fail.Error
type AnyPropertyCallback = PropertyCallback[clonable.Clonable]
type AllPropertiesCallback func(*serialize.JSONProperties) fail.Error

// Metadata contains the core functions of a persistent object
type Metadata[T abstract.Abstract] interface {
	clonable.Clonable

	core() (*Core[T], fail.Error)
	IsNull() bool
	BrowseFolder(ctx context.Context, callback func(buf []byte) fail.Error) fail.Error // walks through host folder and executes a callback for each entry
	Deserialize(ctx context.Context, buf []byte) fail.Error                            // Transforms a slice of bytes in struct
	Read(ctx context.Context, ref string) fail.Error                                   // reads the data from Object Storage using ref as id or name
	ReadByID(ctx context.Context, id string) fail.Error                                // reads the data from Object Storage by id
	Reload(ctx context.Context) fail.Error                                             // Reloads the metadata from the Object Storage, overriding what is in the object
	String() (string, fail.Error)
}

type Consistent interface {
	Exists(context.Context) (bool, fail.Error) // Exists checks if the resource actually exists in provider side (not in stow metadata)
}