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

package propertiesv1

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// HostShare describes a filesystem exported from the host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental/overriding fields
type HostShare struct {
	ID            string            `json:"id"`                        // ID ...
	Name          string            `json:"name"`                      // the name of the share
	Path          string            `json:"path"`                      // the path on the host filesystem that is shared
	PathAcls      string            `json:"path_acls,omitempty"`       // filesystem acls to set on the exported folder
	Type          string            `json:"type,omitempty"`            // export type is lowercase (ie. nfs, glusterfs, ...)
	ShareAcls     string            `json:"share_acls,omitempty"`      // the acls to set on the share
	ShareOptions  string            `json:"share_options,omitempty"`   // the options (other than acls) to set on the share
	ClientsByID   map[string]string `json:"clients_by_id,omitempty"`   // contains the name of the hosts mounting the export, indexed by host ID
	ClientsByName map[string]string `json:"clients_by_name,omitempty"` // contains the ID of the hosts mounting the export, indexed by host GetName
}

// NewHostShare ...
func NewHostShare() *HostShare {
	return &HostShare{
		ClientsByID:   map[string]string{},
		ClientsByName: map[string]string{},
	}
}

// IsNull ...
func (hs *HostShare) IsNull() bool {
	return hs == nil || len(hs.ClientsByID) == 0
}

// Clone ...
func (hs *HostShare) Clone() (clonable.Clonable, error) {
	if hs == nil {
		return nil, fail.InvalidInstanceError()
	}

	nhs := NewHostShare()
	return nhs, nhs.Replace(hs)
}

// Replace ...
func (hs *HostShare) Replace(p clonable.Clonable) error {
	if hs == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*HostShare](p)
	if err != nil {
		return err
	}

	*hs = *src
	hs.ClientsByID = make(map[string]string, len(src.ClientsByID))
	for k, v := range src.ClientsByID {
		hs.ClientsByID[k] = v
	}
	hs.ClientsByName = make(map[string]string, len(src.ClientsByName))
	for k, v := range src.ClientsByName {
		hs.ClientsByName[k] = v
	}
	return nil
}

// HostShares contains information about the shares of the host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental/overriding fields
type HostShares struct {
	ByID   map[string]*HostShare `json:"by_id,omitempty"`
	ByName map[string]string     `json:"by_name,omitempty"`
}

// NewHostShares ...
func NewHostShares() *HostShares {
	return &HostShares{
		ByID:   map[string]*HostShare{},
		ByName: map[string]string{},
	}
}

// IsNull ...
func (hs *HostShares) IsNull() bool {
	return hs == nil || len(hs.ByID) == 0
}

// Clone ...
func (hs *HostShares) Clone() (clonable.Clonable, error) {
	if hs == nil {
		return nil, fail.InvalidInstanceError()
	}

	nhs := NewHostShares()
	return nhs, nhs.Replace(hs)
}

// Replace ...
func (hs *HostShares) Replace(p clonable.Clonable) error {
	if hs == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*HostShares](p)
	if err != nil {
		return err
	}

	hs.ByID = make(map[string]*HostShare, len(src.ByID))
	for k, v := range src.ByID {
		hs.ByID[k] = v
	}
	hs.ByName = make(map[string]string, len(src.ByName))
	for k, v := range src.ByName {
		hs.ByName[k] = v
	}
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.SharesV1, NewHostShares())
}
