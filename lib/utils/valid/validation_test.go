package valid

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_IsIP(t *testing.T) {

	require.EqualValues(t, IsIP("0.0.0.0"), true)
	require.EqualValues(t, IsIP("127...1"), false)
	require.EqualValues(t, IsIP("256.256.256.256"), false)
	require.EqualValues(t, IsIP("172.72.0.1"), true)
	require.EqualValues(t, IsIP("::1"), true)
	require.EqualValues(t, IsIP("2001:0db8:3c4d:0015:0000:d234::3eee:0000"), false)
	require.EqualValues(t, IsIP("2001:0db8:3c4d:0015:0000:d234::3eee::"), false)
	require.EqualValues(t, IsIP("2001:0db8:0000:85a3:0000:0000:ac1f:8001"), true)
	require.EqualValues(t, IsIP("2001:0db8:0:85a3:0:0:ac1f:8001"), true)
	require.EqualValues(t, IsIP("2001:db8:0:85a3::ac1f:8001"), true)
	require.EqualValues(t, IsIP("2001:db8::85a3::ac1f:8001"), false)

}

func Test_IsIPv4(t *testing.T) {

	require.EqualValues(t, IsIPv4("0.0.0.0"), true)
	require.EqualValues(t, IsIPv4("127...1"), false)
	require.EqualValues(t, IsIPv4("256.256.256.256"), false)
	require.EqualValues(t, IsIPv4("172.72.0.1"), true)
	require.EqualValues(t, IsIPv4("::1"), false)
	require.EqualValues(t, IsIPv4("2001:0db8:3c4d:0015:0000:d234::3eee:0000"), false)
	require.EqualValues(t, IsIPv4("2001:0db8:3c4d:0015:0000:d234::3eee::"), false)
	require.EqualValues(t, IsIPv4("2001:0db8:0000:85a3:0000:0000:ac1f:8001"), false)
	require.EqualValues(t, IsIPv4("2001:0db8:0:85a3:0:0:ac1f:8001"), false)
	require.EqualValues(t, IsIPv4("2001:db8:0:85a3::ac1f:8001"), false)
	require.EqualValues(t, IsIPv4("2001:db8::85a3::ac1f:8001"), false)

}

func Test_IsIPv6(t *testing.T) {

	require.EqualValues(t, IsIPv6("0.0.0.0"), false)
	require.EqualValues(t, IsIPv6("127...1"), false)
	require.EqualValues(t, IsIPv6("256.256.256.256"), false)
	require.EqualValues(t, IsIPv6("172.72.0.1"), false)
	require.EqualValues(t, IsIPv6("::1"), true)
	require.EqualValues(t, IsIPv6("2001:0db8:3c4d:0015:0000:d234::3eee:0000"), false)
	require.EqualValues(t, IsIPv6("2001:0db8:3c4d:0015:0000:d234::3eee::"), false)
	require.EqualValues(t, IsIPv6("2001:0db8:0000:85a3:0000:0000:ac1f:8001"), true)
	require.EqualValues(t, IsIPv6("2001:0db8:0:85a3:0:0:ac1f:8001"), true)
	require.EqualValues(t, IsIPv6("2001:db8:0:85a3::ac1f:8001"), true)
	require.EqualValues(t, IsIPv6("2001:db8::85a3::ac1f:8001"), false)

}

func Test_IsAlphanumericWithDashesAndUnderscores(t *testing.T) {

	require.EqualValues(t, IsAlphanumericWithDashesAndUnderscores(""), false)
	require.EqualValues(t, IsAlphanumericWithDashesAndUnderscores("AZaz.+-_"), false)
	require.EqualValues(t, IsAlphanumericWithDashesAndUnderscores("-_0a"), true)
	require.EqualValues(t, IsAlphanumericWithDashesAndUnderscores("0000"), true)
	require.EqualValues(t, IsAlphanumericWithDashesAndUnderscores("-__-"), true)

}
