package integration_tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/integration_tests/enums/Providers"
	"github.com/stretchr/testify/require"
)

func ClusterK8S(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("ClusterK8S", 0, 0, 0, 0, 0, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("deploy -v -d cluster create + --cidr 168.192.200.0/24 --disable remotedesktop " + names.Clusters[0])
	require.Nil(t, err)

	command := "sudo -u cladm -i kubectl run hello-world-za --image=gcr.io/google-samples/node-hello:1.0  --port=8080"
	out, err = GetOutput("broker ssh run " + names.Clusters[0] + "-master-1 -c \"" + command + "\"")
	require.Nil(t, err)

	command = "sudo -u cladm -i bash -c \\\"while kubectl get pods|grep hello-world-za|grep ContainerCreating; do kubectl get pods|grep hello-world-za|grep Running; done\\\""
	out, err = GetOutput("broker ssh run " + names.Clusters[0] + "-master-1 -c \"" + command + "\"")
	require.Nil(t, err)

	out, err = GetOutput("deploy cluster inspect " + names.Clusters[0])
	require.Nil(t, err)

	out, err = GetOutput("deploy cluster delete --yes " + names.Clusters[0])
	require.Nil(t, err)
	fmt.Println(out)
}

func ClusterSwarm(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("ClusterSwarm", 0, 0, 0, 0, 0, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("deploy -v -d cluster create + --cidr 168.192.201.0/24 --disable remotedesktop --flavor SWARM " + names.Clusters[0])
	require.Nil(t, err)

	command := "docker service create --name webtest --publish 8118:80 httpd"
	out, err = GetOutput("broker ssh run " + names.Clusters[0] + "-master-1 -c \"" + command + "\"")
	require.Nil(t, err)

	command = "docker service ls | grep webtest | grep httpd | grep 1/1"
	out, err = GetOutput("broker ssh run " + names.Clusters[0] + "-master-1 -c \"" + command + "\"")
	require.Nil(t, err)

	command = "curl 127.0.0.1:8118"
	out, err = GetOutput("broker ssh run " + names.Clusters[0] + "-master-1 -c \"" + command + "\"")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "It works!"))

	out, err = GetOutput("deploy host check-feature gw-net-" + names.Clusters[0] + " reverseproxy")
	require.Nil(t, err)

	//need --param Password=
	//out, err = GetOutput("deploy -v -d cluster add-feature " + names.Clusters[0] + " remotedesktop --skip-proxy")
	//require.Nil(t, err)

	//out, err = GetOutput("deploy -v -d cluster check-feature " + names.Clusters[0] + " remotedesktop")
	//require.Nil(t, err)

	//out, err = GetOutput("deploy -v -d cluster delete-feature " + names.Clusters[0] + " remotedesktop")
	//require.Nil(t, err)

	out, err = GetOutput("deploy cluster inspect " + names.Clusters[0])
	require.Nil(t, err)

	out, err = GetOutput("deploy cluster delete --yes " + names.Clusters[0])
	require.Nil(t, err)
}
