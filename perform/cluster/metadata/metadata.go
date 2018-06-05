package metadata

/*
* Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"fmt"

	"github.com/CS-SI/SafeScale/perform/cluster/api"
	"github.com/CS-SI/SafeScale/utils"
)

const (
	//Path is the path to use to reach Cluster Definitions/Metadata
	Path = "cluster/"
)

//Record is the cluster definition stored in ObjectStorage
type Record struct {
	//Common contains the common denominator of definition of a cluster
	Common api.Cluster
	//Internal contains the part specific to a cluster; only the code of the Flavor
	// of the cluster knows what to do with Internal.
	Internal interface{}
}

//New creates a new Cluster Metadata
func New(name string) (*Record, error) {
	return &Record{}, nil
}

//Delete removes a cluster metadata
func Delete(name string) error {
	err := utils.DeleteMetadata(Path, name)
	if err != nil {
		return fmt.Errorf("failed to remove cluster definition in Object Storage: %s", err.Error())
	}
	return nil
}

//Read reads metadata of cluster named 'name' from Object Storage
func (r *Record) Read(name string) (bool, error) {
	found, err := utils.FindMetadata(Path, name)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}

	err = utils.ReadMetadata(Path, name, func(buf *bytes.Buffer) error {
		err := gob.NewDecoder(buf).Decode(r)
		if err != nil {
			return err
		}
		return nil
	})
	return true, err
}

//Write saves the content of m to the Object Storage
func (r *Record) Write(name string) error {
	return utils.WriteMetadata(Path, name, r)
}

func init() {
	gob.Register(Record{})
}
