package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/savaki/jq"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/integrationtests"
)

func cleanIp(ip string) string {
	if strings.Contains(ip, "\"") {
		return strings.Replace(ip, "\"", "", -1)
	}
	return ip
}

func checkVIP(netName string, t *testing.T) {
	out, err := integrationtests.GetOutput(fmt.Sprintf("safescale network inspect net-%s", netName))
	require.Nil(t, err)

	op, err := jq.Parse(".result.virtual_ip.private_ip")
	require.Nil(t, err)

	value, err := op.Apply([]byte(out))
	require.Nil(t, err)

	rawValue := cleanIp(string(value))

	out, err = integrationtests.GetOutput(fmt.Sprintf(`safescale ssh run -c "cat /etc/keepalived/keepalived.conf" gw-net-%s`, netName))
	require.Nil(t, err)
	if !strings.Contains(out, rawValue) {
		t.FailNow()
	}

	out, err = integrationtests.GetOutput(fmt.Sprintf(`safescale ssh run -c "cat /etc/keepalived/keepalived.conf" gw2-net-%s`, netName))
	require.Nil(t, err)
	if !strings.Contains(out, rawValue) {
		t.FailNow()
	}
}

func Test_Basic(t *testing.T) {
	netName := "test-keepalived-issue"

	checkVIP(netName, t)
}
