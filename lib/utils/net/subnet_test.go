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
	require.EqualValues(t, err, nil)
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
