package integrationtests // Package integrationtests this package contains integration tests

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func ClusterK8S(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := GetNames("ClusterK8S", 0, 0, 0, 0, 0, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("safescale -v -d cluster create + --cidr 192.168.200.0/24 --disable remotedesktop " + names.Clusters[0])
	require.Nil(t, err)
	_ = out

	command := "sudo -u cladm -i kubectl run hello-world-za --image=gcr.io/google-samples/node-hello:1.0  --port=8080"
	out, err = GetOutput("safescale ssh run " + names.Clusters[0] + "-master-1 -c \"" + command + "\"")
	require.Nil(t, err)
	_ = out

	command = "sudo -u cladm -i bash -c \\\"while kubectl get pods|grep hello-world-za|grep ContainerCreating; do kubectl get pods|grep hello-world-za|grep Running; done\\\""
	out, err = GetOutput("safescale ssh run " + names.Clusters[0] + "-master-1 -c \"" + command + "\"")
	require.Nil(t, err)
	_ = out

	out, err = GetOutput("safescale cluster inspect " + names.Clusters[0])
	require.Nil(t, err)
	_ = out

	out, err = GetOutput("safescale cluster delete --yes " + names.Clusters[0])
	require.Nil(t, err)
	fmt.Println(out)
}
