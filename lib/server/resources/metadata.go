/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// Callback describes the function prototype to use to inspect metadata
type Callback = func(data.Clonable, *serialize.JSONProperties) fail.Error

// Metadata contains the core functions of a persistent object
type Metadata interface {
	cache.Cacheable

	Alter(callback Callback, options ...data.ImmutableKeyValue) fail.Error // protects the data for exclusive write
	BrowseFolder(callback func(buf []byte) fail.Error) fail.Error          // walks through host folder and executes a callback for each entries
	// Carry(clonable data.Clonable) fail.Error                               // links metadata with real data
	// Delete() fail.Error                                                    // deletes the metadata
	Deserialize(buf []byte) fail.Error                                     // Transforms a slice of bytes in struct
	GetService() iaas.Service                                              // returns the iaas.Service used
	Inspect(callback Callback) fail.Error                                  // protects the data for shared read with first reloading data from Object Storage
	Review(callback Callback) fail.Error                                   // protects the data for shared read without reloading first (uses in-memory data); use with caution
	Read(ref string) fail.Error                                            // reads the data from Object Storage using ref as id or name
	ReadByID(id string) fail.Error                                         // reads the data from Object Storage by id
	Reload() fail.Error                                                    // Reloads the metadata from the Object Storage, overriding what is in the object
	Serialize() ([]byte, fail.Error)
}
