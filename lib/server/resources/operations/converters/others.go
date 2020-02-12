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

package converters

// Contains functions that are used to convert from everything else

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
)

// BucketListToProtocol convert a list of string into a *ContainerLsit
func BucketListToProtocol(in []string) *protocol.BucketList {
	var buckets []*protocol.Bucket
	for _, name := range in {
		buckets = append(buckets, &protocol.Bucket{Name: name})
	}
	return &protocol.BucketList{
		Buckets: buckets,
	}
}

func HostStateFromAbstractsToProtocol(in hoststate.Enum) protocol.HostState {
	return protocol.HostState(in)
}
