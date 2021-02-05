/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package safescale

import "github.com/CS-SI/SafeScale/lib/utils/fail"

// Clone makes a copy of HostSizing
func (x *HostSizing) Clone() *HostSizing {
	if x == nil {
		return &HostSizing{}
	}
	return &HostSizing{
		MinCpuCount: x.MinCpuCount,
		MaxCpuCount: x.MaxCpuCount,
		MinRamSize:  x.MinRamSize,
		MaxRamSize:  x.MaxRamSize,
		MinDiskSize: x.MinDiskSize,
		GpuCount:    x.GpuCount,
		MinCpuFreq:  x.MinCpuFreq,
	}
}

func (x *HostSizing) GreaterThan(y *HostSizing) (bool, error) {
	if x == nil {
		return false, fail.InvalidInstanceError()
	}

	if y == nil {
		return false, fail.InvalidParameterError("y", "cannot be nil")
	}

	if x.MinCpuCount < y.MinCpuCount {
		return false, nil
	}

	if x.MinRamSize < y.MinRamSize {
		return false, nil
	}

	if x.MinDiskSize < y.MinDiskSize {
		return false, nil
	}

	if x.GpuCount < y.GpuCount {
		return false, nil
	}

	if x.MinCpuFreq < y.MinCpuFreq {
		return false, nil
	}

	return true, nil
}

func (x *HostDefinition) LowerThan(y *HostDefinition) (bool, error) {
	if x == nil {
		return false, fail.InvalidInstanceError()
	}

	if y == nil {
		return false, fail.InvalidParameterError("y", "cannot be nil")
	}

	less := true

	if x.Sizing.MinCpuCount >= y.Sizing.MinCpuCount {
		less = false
	}
	if x.Sizing.MaxCpuCount >= y.Sizing.MaxCpuCount {
		less = false
	}
	if x.Sizing.MinRamSize >= y.Sizing.MinRamSize {
		less = false
	}
	if x.Sizing.MaxRamSize >= y.Sizing.MaxRamSize {
		less = false
	}
	if x.Sizing.MinDiskSize >= y.Sizing.MinDiskSize {
		less = false
	}
	if x.Sizing.GpuCount >= y.Sizing.GpuCount {
		less = false
	}
	if x.Sizing.MinCpuFreq >= y.Sizing.MinCpuFreq {
		less = false
	}

	return less, nil
}

func (x *HostDefinition) LowerOrEqualThan(y *HostDefinition) (bool, error) {
	if x == nil {
		return false, fail.InvalidInstanceError()
	}

	if y == nil {
		return false, fail.InvalidParameterError("y", "cannot be nil")
	}

	less := true

	if x.Sizing.MinCpuCount > y.Sizing.MinCpuCount {
		less = false
	}
	if x.Sizing.MaxCpuCount > y.Sizing.MaxCpuCount {
		less = false
	}
	if x.Sizing.MinRamSize > y.Sizing.MinRamSize {
		less = false
	}
	if x.Sizing.MaxRamSize > y.Sizing.MaxRamSize {
		less = false
	}
	if x.Sizing.MinDiskSize > y.Sizing.MinDiskSize {
		less = false
	}
	if x.Sizing.GpuCount > y.Sizing.GpuCount {
		less = false
	}
	if x.Sizing.MinCpuFreq > y.Sizing.MinCpuFreq {
		less = false
	}

	return less, nil
}

func (x *HostSizing) LowerOrEqualThan(y *HostSizing) (bool, error) {
	if x == nil {
		return false, fail.InvalidInstanceError()
	}

	gr, err := x.GreaterThan(y)
	if err != nil {
		return false, err
	}

	return !gr, nil
}

// Clone makes a copy of a HostDefinition
func (x *HostDefinition) Clone() *HostDefinition {
	if x == nil {
		return &HostDefinition{}
	}
	return &HostDefinition{
		Name:          x.Name,
		Network:       x.Network,
		CpuCount:      x.CpuCount,
		Ram:           x.Ram,
		Disk:          x.Disk,
		ImageId:       x.ImageId,
		Public:        x.Public,
		GpuCount:      x.GpuCount,
		CpuFreq:       x.CpuFreq,
		Force:         x.Force,
		Sizing:        x.Sizing.Clone(),
		Domain:        x.Domain,
		KeepOnFailure: x.KeepOnFailure,
	}
}
