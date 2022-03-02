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
	ipv4l, ipv4h, err := CIDRToIPv4Range("")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.EqualValues(t, strings.Contains(err.Error(), "cannot be empty string"), true)

	ipv4l, ipv4h, err = CIDRToIPv4Range("0.0.0.0/-4")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.EqualValues(t, strings.Contains(err.Error(), "fail to extract network mask"), true)

	ipv4l, ipv4h, err = CIDRToIPv4Range("127.0.0.1/33")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.EqualValues(t, strings.Contains(err.Error(), "invalid network mask"), true)

	// Almost valid
	ipv4l, ipv4h, err = CIDRToIPv4Range("127.0.0.1")
	require.EqualValues(t, ipv4l, "127.0.0.1")
	require.EqualValues(t, ipv4h, "127.0.0.1")

	ipv4l, ipv4h, err = CIDRToIPv4Range("0/28")
	require.EqualValues(t, ipv4l, "0.0.0.0")
	require.EqualValues(t, ipv4h, "0.0.0.15")

	ipv4l, ipv4h, err = CIDRToIPv4Range("douze.168.0.1/24")
	require.EqualValues(t, ipv4l, "0.168.0.1")
	require.EqualValues(t, ipv4h, "0.168.0.255")

	// valid
	ipv4l, ipv4h, err = CIDRToIPv4Range("127.0.0.1/32")
	require.EqualValues(t, ipv4l, "127.0.0.1")
	require.EqualValues(t, ipv4h, "127.0.0.1")

	ipv4l, ipv4h, err = CIDRToIPv4Range("192.168.0.1/24")
	require.EqualValues(t, ipv4l, "192.168.0.1")
	require.EqualValues(t, ipv4h, "192.168.0.255")

}

func Test_CIDRToUInt32Range(t *testing.T) {

	// Invalid
	ipv4l, ipv4h, err := CIDRToUInt32Range("")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.EqualValues(t, strings.Contains(err.Error(), "cannot be empty string"), true)

	ipv4l, ipv4h, err = CIDRToUInt32Range("0.0.0.0/-4")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.EqualValues(t, strings.Contains(err.Error(), "fail to extract network mask"), true)

	ipv4l, ipv4h, err = CIDRToUInt32Range("127.0.0.1/33")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.EqualValues(t, strings.Contains(err.Error(), "invalid network mask"), true)

	// Almost valid
	ipv4l, ipv4h, err = CIDRToUInt32Range("127.0.0.1")
	require.EqualValues(t, ipv4l, 2130706433)
	require.EqualValues(t, ipv4h, 2130706433)

	// Valid
	ipv4l, ipv4h, err = CIDRToUInt32Range("192.168.0.1/24")
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
		require.EqualValues(t, strings.Contains(err.Error(), "cannot be empty string"), true)
	}

	result, err = IsCIDRRoutable("0.0.0.0/-4")
	require.EqualValues(t, result, false)
	if err == nil {
		t.Error("Expect *fail.ErrInvalidParameter error")
		t.Fail()
	} else {
		require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
		require.EqualValues(t, strings.Contains(err.Error(), "fail to extract network mask"), true)
	}

	result, err = IsCIDRRoutable("127.0.0.1/33")
	require.EqualValues(t, result, false)
	if err == nil {
		t.Error("Expect *fail.ErrInvalidParameter error")
		t.Fail()
	} else {
		require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
		require.EqualValues(t, strings.Contains(err.Error(), "invalid network mask"), true)
	}

	result, err = IsCIDRRoutable("127.0.0.1")
	require.EqualValues(t, err, nil)
	require.EqualValues(t, result, true)

	result, err = IsCIDRRoutable("0/28")
	require.EqualValues(t, err, nil)
	require.EqualValues(t, result, true)

	result, err = IsCIDRRoutable("douze.168.0.1/24")
	require.EqualValues(t, err, nil)
	require.EqualValues(t, result, true)

	result, err = IsCIDRRoutable("127.0.0.1/32")
	require.EqualValues(t, err, nil)
	require.EqualValues(t, result, true)

	result, err = IsCIDRRoutable("192.168.0.1/24")
	require.EqualValues(t, err, nil)
	require.EqualValues(t, result, false)

	// Special not routables

	result, err = IsCIDRRoutable("10.0.0.0/8")
	require.EqualValues(t, err, nil)
	require.EqualValues(t, result, false)

	result, err = IsCIDRRoutable("172.16.0.0/12")
	require.EqualValues(t, err, nil)
	require.EqualValues(t, result, false)

	result, err = IsCIDRRoutable("192.168.0.0/16")
	require.EqualValues(t, err, nil)
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

	var result = false
	for i := range tests {
		result = CIDROverlap(tests[i].ip1, tests[i].ip2)
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
	require.NotEqual(t, err, nil)
	require.EqualValues(t, strings.Contains(err.Error(), "invalid CIDR"), true)
	require.EqualValues(t, result, false)

	source = "192.168.0.1/24"
	target = ""
	result, err = source.Contains(target)
	require.NotEqual(t, err, nil)
	require.EqualValues(t, strings.Contains(err.Error(), "invalid CIDR"), true)
	require.EqualValues(t, result, false)

	source = "192.168.0.1/24"
	target = "192.168.0.1/28"
	result, err = source.Contains(target)
	require.EqualValues(t, err, nil)
	require.EqualValues(t, result, true)

}

type CIDRIntersectsWithTest struct {
	cidr1               CIDRString
	cidr2               CIDRString
	expectError         bool
	expectErrorFragment string
	result              bool
}

func TestCIDRString_IntersectsWith(t *testing.T) {

	tests := []CIDRIntersectsWithTest{
		{
			cidr1:               "",
			cidr2:               "",
			expectError:         true,
			expectErrorFragment: "invalid CIDR",
			result:              false,
		},
		{
			cidr1:               "",
			cidr2:               "192.168.0.1/24",
			expectError:         true,
			expectErrorFragment: "invalid CIDR",
			result:              false,
		},
		{
			cidr1:               "192.168.0.1/24",
			cidr2:               "",
			expectError:         true,
			expectErrorFragment: "invalid CIDR",
			result:              false,
		},
		{
			cidr1:               "192.168.0.1/-1",
			cidr2:               "192.168.0.1/28",
			expectError:         true,
			expectErrorFragment: "invalid CIDR",
			result:              false,
		},
		{
			cidr1:               "192.168.0.1/24",
			cidr2:               "192.168.0.1/-1",
			expectError:         true,
			expectErrorFragment: "invalid CIDR",
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
		require.EqualValues(t, result, tests[i].result)
		if !tests[i].expectError && err != nil {
			t.Error(err)
			t.Fail()
		} else {
			if tests[i].expectError {
				if err == nil {
					t.Error("Expect error")
					t.Fail()
				} else {
					require.EqualValues(t, strings.Contains(err.Error(), tests[i].expectErrorFragment), true)
				}
			}
		}
	}
}
