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

package propertiesv1

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/bucketproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/serialize"
)

// // BucketMount stores information about the mount of a Bucket
// // not FROZEN yet
// type BucketMount struct {
// 	HostID    string `json:"host_id"`    // Device is the name of the device (/dev/... for local mount, host:/path for remote mount)
// 	MountPath string `json:"mount_path"` // Path is the mount point of the device
// }
//
// // NewBucketMount ...
// func NewBucketMount() *BucketMount {
// 	return &BucketMount{}
// }
//
// // IsNull ...
// // satisfies interface data.Clonable
// func (bm *BucketMount) IsNull() bool {
// 	return bm == nil || bm.HostID == ""
// }
//
// // Clone ...
// // satisfies interface data.Clonable
// func (bm BucketMount) Clone() data.Clonable {
// 	return NewBucketMount().Replace(&bm)
// }
//
// // Replace ...
// func (bm *BucketMount) Replace(p data.Clonable) data.Clonable {
// 	// Do not test with isNull(), it's allowed to clone a null value...
// 	if bm == nil || p == nil {
// 		return bm
// 	}
//
// 	src := p.(*BucketMount)
// 	*bm = *src
// 	return bm
// }

// BucketMounts contains information about hosts that havec mounted the bucket
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
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
// (data.Clonable interface)
func (bm *BucketMounts) IsNull() bool {
	return bm == nil || len(bm.ByHostID) == 0
}

// Clone ...  (data.Clonable interface)
func (bm *BucketMounts) Clone() data.Clonable {
	return NewBucketMounts().Replace(bm)
}

// Replace ...  (data.Clonable interface)
func (bm *BucketMounts) Replace(p data.Clonable) data.Clonable {
	// Note: do not validate with IsNull(), it's allowed to replace a null value...
	if bm == nil || p == nil {
		return bm
	}

	src, _ := p.(*BucketMounts) // FIXME: Replace should also return an error
	bm.ByHostID = make(map[string]string, len(src.ByHostID))
	for k, v := range src.ByHostID {
		bm.ByHostID[k] = v
	}
	bm.ByHostName = make(map[string]string, len(src.ByHostName))
	for k, v := range src.ByHostName {
		bm.ByHostName[k] = v
	}
	return bm
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.bucket", bucketproperty.MountsV1, NewBucketMounts())
}
