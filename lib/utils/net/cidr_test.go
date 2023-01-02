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

package net

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_CIDRToIPv4Range(t *testing.T) {

	// Invalid
	_, _, err := CIDRToIPv4Range("")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, err.Error(), "cannot be empty string")

	_, _, err = CIDRToIPv4Range("0.0.0.0/-4")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, err.Error(), "fail to extract network mask")

	_, _, err = CIDRToIPv4Range("127.0.0.1/33")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, err.Error(), "invalid network mask")

	// Almost valid
	ipv4l, ipv4h, err := CIDRToIPv4Range("127.0.0.1")
	require.Nil(t, err)
	require.EqualValues(t, ipv4l, "127.0.0.1")
	require.EqualValues(t, ipv4h, "127.0.0.1")

	ipv4l, ipv4h, err = CIDRToIPv4Range("0/28")
	require.Nil(t, err)
	require.EqualValues(t, ipv4l, "0.0.0.0")
	require.EqualValues(t, ipv4h, "0.0.0.15")

	ipv4l, ipv4h, err = CIDRToIPv4Range("douze.168.0.1/24")
	require.Nil(t, err)
	require.EqualValues(t, ipv4l, "0.168.0.1")
	require.EqualValues(t, ipv4h, "0.168.0.255")

	// valid
	ipv4l, ipv4h, err = CIDRToIPv4Range("127.0.0.1/32")
	require.Nil(t, err)
	require.EqualValues(t, ipv4l, "127.0.0.1")
	require.EqualValues(t, ipv4h, "127.0.0.1")

	ipv4l, ipv4h, err = CIDRToIPv4Range("192.168.0.1/24")
	require.Nil(t, err)
	require.EqualValues(t, ipv4l, "192.168.0.1")
	require.EqualValues(t, ipv4h, "192.168.0.255")

}

func Test_CIDRToUInt32Range(t *testing.T) {

	// Invalid
	_, _, err := CIDRToUInt32Range("")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, err.Error(), "cannot be empty string")

	_, _, err = CIDRToUInt32Range("0.0.0.0/-4")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, err.Error(), "fail to extract network mask")

	_, _, err = CIDRToUInt32Range("127.0.0.1/33")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, err.Error(), "invalid network mask")

	// Almost valid
	ipv4l, ipv4h, err := CIDRToUInt32Range("127.0.0.1")
	require.Nil(t, err)
	require.EqualValues(t, ipv4l, 2130706433)
	require.EqualValues(t, ipv4h, 2130706433)

	// Valid
	ipv4l, ipv4h, err = CIDRToUInt32Range("192.168.0.1/24")
	require.Nil(t, err)
	require.EqualValues(t, uint64(ipv4l), uint64(3232235521))
	require.EqualValues(t, uint64(ipv4h), uint64(3232235775))
}

func Test_IsCIDRRoutable(t *testing.T) {

	result, err := IsCIDRRoutable("")
	require.EqualValues(t, result, false)
	if err == nil {
		t.Error("Expect *fail.ErrInvalidParameter error")
		t.Fail()
	} else {
		require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
		require.Contains(t, err.Error(), "cannot be empty string")
	}

	result, err = IsCIDRRoutable("0.0.0.0/-4")
	require.EqualValues(t, result, false)
	if err == nil {
		t.Error("Expect *fail.ErrInvalidParameter error")
		t.Fail()
	} else {
		require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
		require.Contains(t, err.Error(), "fail to extract network mask")
	}

	result, err = IsCIDRRoutable("127.0.0.1/33")
	require.EqualValues(t, result, false)
	if err == nil {
		t.Error("Expect *fail.ErrInvalidParameter error")
		t.Fail()
	} else {
		require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
		require.Contains(t, err.Error(), "invalid network mask")
	}

	result, err = IsCIDRRoutable("127.0.0.1")
	require.Nil(t, err)
	require.EqualValues(t, result, true)

	result, err = IsCIDRRoutable("0/28")
	require.Nil(t, err)
	require.EqualValues(t, result, true)

	result, err = IsCIDRRoutable("douze.168.0.1/24")
	require.Nil(t, err)
	require.EqualValues(t, result, true)

	result, err = IsCIDRRoutable("127.0.0.1/32")
	require.Nil(t, err)
	require.EqualValues(t, result, true)

	result, err = IsCIDRRoutable("192.168.0.1/24")
	require.Nil(t, err)
	require.EqualValues(t, result, false)

	// Special not routables

	result, err = IsCIDRRoutable("10.0.0.0/8")
	require.Nil(t, err)
	require.EqualValues(t, result, false)

	result, err = IsCIDRRoutable("172.16.0.0/12")
	require.Nil(t, err)
	require.EqualValues(t, result, false)

	result, err = IsCIDRRoutable("192.168.0.0/16")
	require.Nil(t, err)
	require.EqualValues(t, result, false)

}

type CIDROverlapTest struct {
	ip1    net.IPNet
	ip2    net.IPNet
	result bool
}

func Test_CIDROverlap(t *testing.T) {

	tests := []CIDROverlapTest{
		{
			ip1: net.IPNet{
				IP:   net.IPv4(127, 0, 0, 1),
				Mask: net.CIDRMask(32, 32),
			},
			ip2: net.IPNet{
				IP:   net.IPv4(127, 0, 0, 1),
				Mask: net.CIDRMask(32, 32),
			},
			result: true,
		},
		{
			ip1: net.IPNet{
				IP:   net.IPv4(172, 12, 0, 1),
				Mask: net.CIDRMask(16, 32),
			},
			ip2: net.IPNet{
				IP:   net.IPv4(172, 12, 15, 1),
				Mask: net.CIDRMask(16, 32),
			},
			result: true,
		},
		{
			ip1: net.IPNet{
				IP:   net.IPv4(172, 12, 0, 1),
				Mask: net.CIDRMask(24, 32),
			},
			ip2: net.IPNet{
				IP:   net.IPv4(172, 12, 15, 1),
				Mask: net.CIDRMask(24, 32),
			},
			result: false,
		},
		{
			ip1: net.IPNet{
				IP:   net.IPv4(0, 0, 0, 0),
				Mask: net.CIDRMask(0, 32),
			},
			ip2: net.IPNet{
				IP:   net.IPv4(0, 0, 0, 0),
				Mask: net.CIDRMask(0, 32),
			},
			result: true,
		},
	}

	for i := range tests {
		result := CIDROverlap(tests[i].ip1, tests[i].ip2)
		require.EqualValues(t, result, tests[i].result)
	}

}

func TestCIDRString_Contains(t *testing.T) {

	var (
		source CIDRString
		target CIDRString
		result bool
		err    error
	)

	source = ""
	target = "192.168.0.1/28"
	result, err = source.Contains(target)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "invalid CIDR")
	require.False(t, result)

	source = "192.168.0.1/24"
	target = ""
	result, err = source.Contains(target)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "invalid CIDR")
	require.False(t, result)

	source = "192.168.0.1/24"
	target = "192.168.0.1/28"
	result, err = source.Contains(target)
	require.Nil(t, err)
	require.True(t, result)

}

type CIDRIntersectsWithTest struct {
	cidr1               CIDRString
	cidr2               CIDRString
	expectError         bool
	expectErrorFragment string
	result              bool
}

func TestDockerIntersect(t *testing.T) {
	var docker CIDRString
	var aSubNet CIDRString
	var outSubNet CIDRString

	docker = "172.17.0.0/16"
	aSubNet = "172.17.4.0/24"
	r, err := docker.IntersectsWith(aSubNet)
	if err != nil {
		t.Fail()
	}
	require.True(t, r)

	outSubNet = "172.16.0.0/15"
	r, err = docker.IntersectsWith(outSubNet)
	if err != nil {
		t.Fail()
	}
	require.True(t, r)
}

func TestDockerIntersect2(t *testing.T) {
	var docker CIDRString
	var aSubNet CIDRString

	docker = "192.168.10.0/28"
	aSubNet = "172.12.0.1/28"
	r, err := docker.IntersectsWith(aSubNet)
	if err != nil {
		t.FailNow()
	}
	require.False(t, r)
}

func TestDockerIntersect3(t *testing.T) {
	var docker CIDRString
	var aSubNet CIDRString

	docker = "10.0.0.0/22"
	aSubNet = "10.0.1.0/24"
	r, err := docker.IntersectsWith(aSubNet)
	if err != nil {
		t.FailNow()
	}
	require.True(t, r)
}

func TestCIDRString_IntersectsWith(t *testing.T) {

	tests := []CIDRIntersectsWithTest{
		{
			cidr1:               "",
			cidr2:               "",
			expectError:         true,
			expectErrorFragment: "invalid",
			result:              false,
		},
		{
			cidr1:               "",
			cidr2:               "192.168.0.1/24",
			expectError:         true,
			expectErrorFragment: "invalid",
			result:              false,
		},
		{
			cidr1:               "192.168.0.1/24",
			cidr2:               "",
			expectError:         true,
			expectErrorFragment: "invalid",
			result:              false,
		},
		{
			cidr1:               "192.168.0.1/-1",
			cidr2:               "192.168.0.1/28",
			expectError:         true,
			expectErrorFragment: "invalid",
			result:              false,
		},
		{
			cidr1:               "192.168.0.1/24",
			cidr2:               "192.168.0.1/-1",
			expectError:         true,
			expectErrorFragment: "invalid",
			result:              false,
		},
		{
			cidr1:               "0.0.0.0/0",
			cidr2:               "255.255.255.255/32",
			expectError:         false,
			expectErrorFragment: "",
			result:              true,
		},
		{
			cidr1:               "255.255.255.255/32",
			cidr2:               "0.0.0.0/0",
			expectError:         false,
			expectErrorFragment: "",
			result:              true,
		},
		{
			cidr1:               "192.168.0.1/24",
			cidr2:               "192.168.0.1/28",
			expectError:         false,
			expectErrorFragment: "",
			result:              true,
		},
		{
			cidr1:               "192.168.0.1/28",
			cidr2:               "192.168.0.1/24",
			expectError:         false,
			expectErrorFragment: "",
			result:              true,
		},
		{
			cidr1:               "192.168.10.0/28",
			cidr2:               "172.12.0.1/28",
			expectError:         false,
			expectErrorFragment: "",
			result:              false,
		},
	}

	var (
		result bool
		err    error
	)

	for i := range tests {
		result, err = tests[i].cidr1.IntersectsWith(tests[i].cidr2)
		if (!tests[i].expectError && err != nil) || (tests[i].expectError && err == nil) {
			t.Error(err)
			t.Fail()
		} else {
			if result != tests[i].result {
				t.Errorf("Test %d failed", i)
			}
			require.EqualValues(t, result, tests[i].result)
			if tests[i].expectError {
				if err == nil {
					t.Errorf("Expected error in test %d", i)
					t.Fail()
				} else {
					if !strings.Contains(err.Error(), tests[i].expectErrorFragment) {
						t.Errorf("%s not found in %s for test %d", tests[i].expectErrorFragment, err.Error(), i)
					}
					require.Contains(t, err.Error(), tests[i].expectErrorFragment)
				}
			}
		}
	}
}
