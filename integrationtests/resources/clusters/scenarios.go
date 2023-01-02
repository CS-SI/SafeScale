//go:build (integration && clustertests) || allintegration
// +build integration,clustertests allintegration

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

package clusters // Package clusters this package contains integration tests of clusters

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
)

func ClusterK8S(t *testing.T) {
	names := helpers.GetNames("ClusterK8S", 0, 0, 0, 0, 0, 1, 0, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale -v -d cluster create --cidr 192.168.200.0/24 --disable remotedesktop " + names.Clusters[0])
	require.Nil(t, err)
	_ = out

	command := "sudo -u cladm -i kubectl run hello-world-za --image=gcr.io/google-samples/node-hello:1.0  --port=8080"
	out, err = helpers.GetOutput("safescale ssh run " + names.Clusters[0] + "-master-1 -c \"" + command + "\"")
	require.Nil(t, err)
	_ = out

	command = "sudo -u cladm -i bash -c \\\"while kubectl get pods|grep hello-world-za|grep ContainerCreating; do kubectl get pods|grep hello-world-za|grep Running; done\\\""
	out, err = helpers.GetOutput("safescale ssh run " + names.Clusters[0] + "-master-1 -c \"" + command + "\"")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale cluster inspect " + names.Clusters[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale cluster delete --yes " + names.Clusters[0])
	require.Nil(t, err)
	fmt.Println(out)
}

func Helm(t *testing.T) {
	t.Skip("Test_Helm not implemented")
	// TODO: Implement integration test
}

func Kubectl(t *testing.T) {
	t.Skip("Test_Kubectl not implemented")
	// TODO: Implement integration test
}

func init() {
}
