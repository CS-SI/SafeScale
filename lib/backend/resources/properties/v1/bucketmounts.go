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

package propertiesv1

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/bucketproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// BucketMounts contains information about hosts that have mounted the bucket
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental/overriding fields
type BucketMounts struct {
	ByHostID   map[string]string `json:"by_host_id"`
	ByHostName map[string]string `json:"by_host_name"`
}

// NewBucketMounts ...
func NewBucketMounts() *BucketMounts {
	return &BucketMounts{
		ByHostID:   map[string]string{},
		ByHostName: map[string]string{},
	}
}

// IsNull ...
// (clonable.Clonable interface)
func (bm *BucketMounts) IsNull() bool {
	return bm == nil || len(bm.ByHostID) == 0
}

// Clone ...  (clonable.Clonable interface)
func (bm *BucketMounts) Clone() (clonable.Clonable, error) {
	if bm == nil {
		return nil, fail.InvalidInstanceError()
	}

	nbm := NewBucketMounts()
	return nbm, nbm.Replace(bm)
}

// Replace ...  (clonable.Clonable interface)
func (bm *BucketMounts) Replace(p clonable.Clonable) error {
	if bm == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*BucketMounts](p)
	if err != nil {
		return err
	}

	bm.ByHostID = make(map[string]string, len(src.ByHostID))
	for k, v := range src.ByHostID {
		bm.ByHostID[k] = v
	}
	bm.ByHostName = make(map[string]string, len(src.ByHostName))
	for k, v := range src.ByHostName {
		bm.ByHostName[k] = v
	}
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.bucket", bucketproperty.MountsV1, NewBucketMounts())
}
