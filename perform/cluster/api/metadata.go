package api

/*
* Copyright 2015-2018, CS Systemes d'Information, http://www.c-s.fr
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

import (
	"bytes"
	"encoding/gob"

	"github.com/CS-SI/SafeScale/utils"
)

//Metadata is the cluster definition stored in ObjectStorage
type Metadata struct {
	//Common contains the common denominator of definition of a cluster
	Common Cluster
	//Internal contains the part specific to a cluster; only the code of the Flavor
	// of the cluster knows what to do with Internal.
	Internal interface{}
}

//New creates a new Cluster Metadata
func New(name string) (*Metadata, error) {
	return &Metadata{}, nil
}

//Read reads metadata of cluster named 'name' from Object Storage
func (data *Metadata) Read(name string) error {
	found, err := utils.FindMetadata(ClusterMetadataPath, name)
	if !found {
		return err
	}

	err = utils.ReadMetadata(ClusterMetadataPath, name, func(buf *bytes.Buffer) error {
		err := gob.NewDecoder(buf).Decode(data)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

//Write saves the content of m to the Object Storage
func (data *Metadata) Write(name string) error {
	return utils.WriteMetadata(ClusterMetadataPath, name, data)
}
