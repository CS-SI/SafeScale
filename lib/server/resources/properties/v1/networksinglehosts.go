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
	"math"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
)

const (
	// SingleHostsCIDRMaskAddition contains the bits added as network part for single Host CIDR
	// Note: AWS limits netmask from /8 to /28, hence the 12...
	SingleHostsCIDRMaskAddition = 12
)

var (
	// SingleHostsMaxCIDRSlotValue contains the max index usable in function lib/utils/net.NthIncludedSubnet() to build CIDR
	SingleHostsMaxCIDRSlotValue = uint(math.Pow(2, SingleHostsCIDRMaskAddition) - 1)
)

type FreeCIDRSlot struct {
	First uint // contains the index of the first available CIDR (to use in lib/utils/net.NthIncludedSubnet() to find corresponding CIDR)
	Last  uint // contains the index of the last available CIDR
}

// NetworkSingleHosts contains additional information describing the CIDR used for single Hosts
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type NetworkSingleHosts struct {
	FreeSlots []FreeCIDRSlot `json:"free_slots,omitempty"` // contains a list of free CIDR in Network for single Hosts
}

// NewNetworkSingleHosts ...
func NewNetworkSingleHosts() *NetworkSingleHosts {
	return &NetworkSingleHosts{}
}

// IsNull ...
// (data.Clonable interface)
func (nsh *NetworkSingleHosts) IsNull() bool {
	return nsh == nil || len(nsh.FreeSlots) == 0
}

// Clone ... (data.Clonable interface)
func (nsh NetworkSingleHosts) Clone() data.Clonable {
	return NewNetworkSingleHosts().Replace(&nsh)
}

// Replace ... (data.Clonable interface)
func (nsh *NetworkSingleHosts) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if nsh == nil || p == nil {
		return nsh
	}

	// FIXME: Replace should also return an error
	src, _ := p.(*NetworkSingleHosts) // nolint
	nsh.FreeSlots = make([]FreeCIDRSlot, len(src.FreeSlots))
	copy(nsh.FreeSlots, src.FreeSlots)
	return nsh
}

// ReserveSlot returns the first free slot and remove it from list
func (nsh *NetworkSingleHosts) ReserveSlot() (index uint) {
	if len(nsh.FreeSlots) == 0 {
		index = 1
		nsh.FreeSlots = append(nsh.FreeSlots, FreeCIDRSlot{First: 2, Last: SingleHostsMaxCIDRSlotValue})
	} else {
		firstFreeSlot := nsh.FreeSlots[0]
		index = firstFreeSlot.First
		firstFreeSlot.First++
		if firstFreeSlot.First > firstFreeSlot.Last {
			nsh.FreeSlots = nsh.FreeSlots[1:]
		} else {
			nsh.FreeSlots[0] = firstFreeSlot
		}
	}
	return index
}

// FreeSlot frees a slot
func (nsh *NetworkSingleHosts) FreeSlot(index uint) {
	var inserted bool
	for i := 0; i < len(nsh.FreeSlots); i++ {
		first := nsh.FreeSlots[i].First
		if index < first {
			if index+1 == first {
				nsh.FreeSlots[i].First = index
			} else {
				nsh.FreeSlots = append([]FreeCIDRSlot{{First: index, Last: index}}, nsh.FreeSlots...)
			}
			inserted = true
			break
		}

		last := nsh.FreeSlots[i].Last
		if index > last {
			if index == last+1 {
				nsh.FreeSlots[i].Last = index
				inserted = true
				break
			}
		}

		if i < len(nsh.FreeSlots)-1 {
			if index < nsh.FreeSlots[i+1].First-1 {
				if i < len(nsh.FreeSlots)-1 {
					newStart := nsh.FreeSlots[:i]
					newStart = append(newStart, FreeCIDRSlot{First: index, Last: index})
					nsh.FreeSlots = append(newStart, nsh.FreeSlots[i+1:]...)
				}
				inserted = true
				break
			}
		}
	}
	if !inserted {
		nsh.FreeSlots = append(nsh.FreeSlots, FreeCIDRSlot{First: index, Last: index})
	}

	if len(nsh.FreeSlots) > 1 {
		// merge adjacent slots
		merged := []FreeCIDRSlot{nsh.FreeSlots[0]}
		current := 0
		for i := 1; i < len(nsh.FreeSlots); i++ {
			// if has partial cover
			if merged[current].Last >= nsh.FreeSlots[i].First {
				merged[current].Last = nsh.FreeSlots[i].Last
			} else {
				merged = append(merged, nsh.FreeSlots[i])
				current++
			}
		}
		nsh.FreeSlots = merged
	}

}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.network", networkproperty.SingleHostsV1, NewNetworkSingleHosts())
}
