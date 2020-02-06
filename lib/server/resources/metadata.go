/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// Callback describes the function prototype to use
type Callback func(data.Clonable, *serialize.JSONProperties) error

// Metadata contains the core functions of a persistent object
type Metadata interface {
	Service() iaas.Service // Service returns the iaas.Service used to create/load the persistency object
	// Properties(task concurrency.Task) (*serialize.JSONProperties, error)       // Properties returns the extension of the cluster
	Inspect(task concurrency.Task, callback Callback) error                    // Inspect protects the data for shared read
	Alter(task concurrency.Task, callback Callback) error                      // Alter protects the data for exclusive write
	Carry(task concurrency.Task, clonable data.Clonable) error                 // Carry links metadata with real data
	Read(task concurrency.Task, ref string) error                              // Read gets the data from Object Storage
	Reload(task concurrency.Task) error                                        // reload Reloads the metadata from the Object Storage, overriding what is in the object
	BrowseFolder(task concurrency.Task, callback func(buf []byte) error) error // Browse walks through host folder and executes a callback for each entries
	Delete(task concurrency.Task) error                                        // Delete deletes the matadata
}
