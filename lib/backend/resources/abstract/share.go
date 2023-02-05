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

package abstract

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	ShareKind = "share"

	sharesFolderName = "shares"
)

// Share contains information about a Share
type Share struct {
	*core

	HostID    string `json:"host_id"`    // contains the ID of the host serving the Share
	HostName  string `json:"host_name"`  // contains the name of the host serving the Share
	ID        string `json:"id"`         // contains the ID of the Share
	ShareID   string `json:"share_id"`   // DEPRECATED: contains the ID of the Share
	ShareName string `json:"share_name"` // DEPRECATED: moved inside Core.Name
}

// NewShare creates a new instance of Share
func NewShare(opts ...Option) (*Share, fail.Error) {
	opts = append(opts, withKind(ShareKind))
	c, xerr := newCore(opts...)
	if xerr != nil {
		return nil, xerr
	}

	sn := &Share{
		core: c,
	}
	return sn, nil
}

// NewEmptyShare creates an empty, unnamed Share instance
func NewEmptyShare() *Share {
	out, _ := NewShare()
	return out
}

// GetID returns the ID of the Share
// satisfies interface data.Identifiable
func (si Share) GetID() (string, error) {
	if si.ID == "" && si.ShareID != "" {
		si.ID = si.ShareID
	}
	return si.ID, nil
}

// GetName returns the name of the Share
// satisfies interface data.Identifiable
func (si Share) GetName() string {
	if si.Name == "" && si.ShareName != "" {
		si.Name = si.ShareName
	}
	return si.Name
}

// Serialize ...
// satisfies interface data.Serializable
func (si Share) Serialize() ([]byte, fail.Error) {
	r, err := json.Marshal(&si)
	return r, fail.Wrap(err)
}

// Deserialize ...
// satisfies interface data.Serializable
func (si *Share) Deserialize(buf []byte) (ferr fail.Error) {
	defer fail.OnPanic(&ferr) // json.Unmarshal may panic
	return fail.Wrap(json.Unmarshal(buf, si))
}

// IsNull ...
// satisfies interface clonable.Clonable
func (si *Share) IsNull() bool {
	return si == nil || (si.HostID == "" && (si.ID == "" && si.ShareID == ""))
}

// Clone ...
// satisfies interface clonable.Clonable
func (si *Share) Clone() (clonable.Clonable, error) {
	if valid.IsNull(si) {
		return nil, fail.InvalidInstanceError()
	}

	newShareItem := *si
	return &newShareItem, nil
}

// Replace ...
// satisfies interface clonable.Clonable
// may panic
func (si *Share) Replace(p clonable.Clonable) error {
	if valid.IsNull(si) {
		return fail.InvalidInstanceError()
	}
	if p == nil {
		return fail.InvalidParameterCannotBeNilError("p")
	}

	src, err := clonable.Cast[*Share](p)
	if err != nil {
		return err
	}

	si.HostID = src.HostID
	si.HostName = src.HostName
	si.ID = src.ID
	return si.core.Replace(src.core)
}
