//go:build (integration && featuretests) || allintegration
// +build integration,featuretests allintegration

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

package ansiblecluster

import (
	"fmt"
	"testing"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
	"github.com/stretchr/testify/require"
)

func AnsibleWrongZipPlaylist(t *testing.T) {
	name := "player0"

	out, err := helpers.GetOutput(fmt.Sprintf("safescale cluster create -F BOH -C Small --cidr 192.168.52.0/24 %s", name))
	require.Nil(t, err)

	defer func() {
		_, err := helpers.GetOutput(fmt.Sprintf("safescale cluster delete -f -y %s", name))
		require.Nil(t, err)
	}()

	// check for success and name
	var res string
	res, err = helpers.RunJq(out, "-r .status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	res, err = helpers.RunJq(out, "-r .result.name")
	require.Nil(t, err)
	require.Equal(t, name, res)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale cluster ansible playbook %s ./playbook-failure-wrong-rolename.zip", name))
	require.Nil(t, err)
	require.NotContains(t, out, "ok=20")
}

func AnsibleGoodZipPlaylist(t *testing.T) {
	name := "player1"

	out, err := helpers.GetOutput(fmt.Sprintf("safescale cluster create -F BOH -C Small --cidr 192.168.53.0/24 %s", name))
	require.Nil(t, err)

	defer func() {
		_, err := helpers.GetOutput(fmt.Sprintf("safescale cluster delete -f -y %s", name))
		require.Nil(t, err)
	}()

	// check for success and name
	var res string
	res, err = helpers.RunJq(out, "-r .status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	res, err = helpers.RunJq(out, "-r .result.name")
	require.Nil(t, err)
	require.Equal(t, name, res)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale cluster ansible playbook %s ./playbook-success.zip", name))
	require.Nil(t, err)
	require.Contains(t, out, "ok=20")
}

func init() {
	helpers.InSection("features").
		AddScenario(AnsibleWrongZipPlaylist).
		AddScenario(AnsibleGoodZipPlaylist)
}
