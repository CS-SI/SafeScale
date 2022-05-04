//go:build integrationtests && (buckets || all)
// +build integrationtests
// +build buckets all

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

package buckets

// func CreateNetworkWithoutSubnet(t *testing.T, provider providers.Enum) {
// 	names := helpers.GetNames("BasicTest", 0, 0, 0, 2, 1, 0)
// 	names.TearDown()
// 	defer names.TearDown()
//
// 	out, err := helpers.GetOutput("safescale network list")
// 	fmt.Println(out)
// 	require.Nil(t, err)
//
// 	fmt.Println("Creating network " + names.Networks[0])
//
// 	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.40.0/24 --empty")
// 	fmt.Println(out)
// 	require.Nil(t, err)
//
// 	out, err = helpers.GetOutput("safescale network inspect " + names.Networks[0])
// 	require.Nil(t, err)
// 	// FIXME: check there is no subnet attached to network
// }

func allBucketScenarios() {
	// helpers.InSection("bucket").
	//  AddScenario(CreateNetworkWithoutSubnet)
}

func init() {
	allBucketScenarios()
}
