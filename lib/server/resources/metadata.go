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

package resources

import (
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/server/resources.Metadata -o mocks/mock_metadata.go

// Callback describes the function prototype to use to inspect metadata
type Callback = func(data.Clonable, *serialize.JSONProperties) fail.Error

//go:generate gowrap gen -g -p github.com/CS-SI/SafeScale/v22/lib/server/resources -i Metadata -t ./microfallback.tmpl -o mfall.go -l ""

// Metadata contains the core functions of a persistent object
type Metadata interface {
	IsNull() bool
	Alter(callback Callback, options ...data.ImmutableKeyValue) fail.Error // protects the data for exclusive write
	BrowseFolder(callback func(buf []byte) fail.Error) fail.Error          // walks through host folder and executes a callback for each entry
	Deserialize(buf []byte) fail.Error                                     // Transforms a slice of bytes in struct
	Inspect(callback Callback) fail.Error                                  // protects the data for shared read with first reloading data from Object Storage
	Review(callback Callback) fail.Error                                   // protects the data for shared read without reloading first (uses in-memory data); use with caution
	Read(ref string) fail.Error                                            // reads the data from Object Storage using ref as id or name
	ReadByID(id string) fail.Error                                         // reads the data from Object Storage by id
	Reload() fail.Error                                                    // Reloads the metadata from the Object Storage, overriding what is in the object
	Sdump() (string, fail.Error)
	Service() iaas.Service // returns the iaas.Service used
}

type Consistent interface {
	Exists() (bool, fail.Error)
}

/*
//go:generate gowrap gen -g -p github.com/CS-SI/SafeScale/v22/lib/server/resources -i RawMetadata -t ./microfallback.tmpl -o breakeven.go -l ""

type RawMetadata interface {
	IsNull() bool
	Alter(callback Callback, options ...data.ImmutableKeyValue) error // protects the data for exclusive write
	BrowseFolder(callback func(buf []byte) error) error          // walks through host folder and executes a callback for each entry
	Deserialize(buf []byte) error                                     // Transforms a slice of bytes in struct
	Inspect(callback Callback) error                                  // protects the data for shared read with first reloading data from Object Storage
	Review(callback Callback) error                                   // protects the data for shared read without reloading first (uses in-memory data); use with caution
	Read(ref string) error                                            // reads the data from Object Storage using ref as id or name
	ReadByID(id string) error                                         // reads the data from Object Storage by id
	Reload() error                                 // Reloads the metadata from the Object Storage, overriding what is in the object
	Sdump() (string, error)
	Service() iaas.Service // returns the iaas.Service used
}
*/
