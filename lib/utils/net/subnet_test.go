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

package net

import (
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_FirstIncludedSubnet(t *testing.T) {

	ip := net.IPNet{
		IP:   net.IPv4(127, 0, 0, 1),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}
	result, err := FirstIncludedSubnet(ip, 4)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	require.EqualValues(t, result.Mask.String(), "fffffff0")

}

func Test_NthIncludedSubnet(t *testing.T) {

	ip := net.IPNet{
		IP:   net.IPv4(127, 0, 0, 1),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}

	result, err := FirstIncludedSubnet(ip, 0)
	if err == nil {
		t.Error("Expect *fail.ErrOverflow error")
		t.Fail()
	}
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrOverflow")

	result, err = FirstIncludedSubnet(ip, 2)
	require.Nil(t, err)
	parentLen, addrLen := result.Mask.Size()
	require.EqualValues(t, parentLen, 26)
	require.EqualValues(t, addrLen, 32)

	result, err = FirstIncludedSubnet(ip, 33)
	if err == nil {
		t.Error("Expect *fail.ErrOverflow error")
		t.Fail()
	}
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrOverflow")

}
