package ssh

import (
	"os"
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	"github.com/stretchr/testify/require"
)

func Test_defaultSSHConnectorFactory(t *testing.T) {

	SetCustomConnectorFactory(nil)

	cfg := ssh.NewConfig("Hostname", "IPaddr", 22, "User", "PrivateKey", 0, "", nil, nil)

	conn, xerr := defaultSSHConnectorFactory(cfg)
	require.Nil(t, xerr)
	conntype, xerr := GetDefaultConnectorType()
	require.Nil(t, xerr)

	require.EqualValues(t, reflect.TypeOf(conn).String(), "*bycli.Profile")
	require.EqualValues(t, conntype, "cli")

	os.Setenv("SAFESCALE_DEFAULT_SSH", "cli")

	conn, xerr = defaultSSHConnectorFactory(cfg)
	require.Nil(t, xerr)
	conntype, xerr = GetDefaultConnectorType()
	require.Nil(t, xerr)

	require.EqualValues(t, reflect.TypeOf(conn).String(), "*bycli.Profile")
	require.EqualValues(t, conntype, "cli")

	os.Setenv("SAFESCALE_DEFAULT_SSH", "lib")

	conn, xerr = defaultSSHConnectorFactory(cfg)
	require.Nil(t, xerr)
	conntype, xerr = GetDefaultConnectorType()
	require.Nil(t, xerr)

	require.EqualValues(t, reflect.TypeOf(conn).String(), "*bylib.Profile")
	require.EqualValues(t, conntype, "lib")

	os.Setenv("SAFESCALE_DEFAULT_SSH", "any")

	conn, xerr = defaultSSHConnectorFactory(cfg)
	require.Nil(t, xerr)
	conntype, xerr = GetDefaultConnectorType()
	require.Nil(t, xerr)

	require.EqualValues(t, reflect.TypeOf(conn).String(), "*bycli.Profile")
	require.EqualValues(t, conntype, "cli")

}
