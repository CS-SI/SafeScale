package integration_tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/integration_tests/enums/Providers"
	"github.com/stretchr/testify/require"
)

//K8S flavored clusters is not working -- WIP
func ClusterK8S(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("ClusterK8S", 0, 0, 0, 0, 0, 1)
	names.TearDown()
	//defer names.TearDown()

	out, err := GetOutput("deploy cluster create + --cidr 168.192.200.0/24 --disable remotedesktop " + names.Clusters[0])
	fmt.Println("Out : ", out)
	fmt.Println("Err : ", err)
	require.Nil(t, err)
}

func ClusterSwarm(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("ClusterSwarm", 0, 0, 0, 0, 0, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("deploy cluster create + --cidr 168.192.201.0/24 --disable remotedesktop --flavor SWARM " + names.Clusters[0])
	fmt.Println("Out : ", out)
	fmt.Println("Err : ", err)
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run " + names.Clusters[0] + " -c \"docker service create --name webtest --publish 8118:80 httpd\"")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run " + names.Clusters[0] + " -c \"docker service ls | grep webtest | grep httpd | grep 1/1\"")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run " + names.Clusters[0] + " -c \"curl 127.0.0.1:8118\"")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "It works!"))

	out, err = GetOutput("deploy host check-feature " + names.Clusters[0] + " reverseproxy")
	require.Nil(t, err)
}
