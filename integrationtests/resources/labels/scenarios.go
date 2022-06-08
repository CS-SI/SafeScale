//go:build (integration && labeltests) || allintegration
// +build integration,labeltests allintegration

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

package labels

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

func LabelBase(t *testing.T) {
	names := helpers.GetNames("LabelBase", 0, 1, 1, 1, 1, 0, 1, 0)
	names.TearDown()
	defer names.TearDown()

	fmt.Println("Creating network " + names.Networks[0])
	out, err := helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.43.0/24")
	_ = out
	require.Nil(t, err)

	fmt.Println("Listing Labels")
	out, err = helpers.GetOutput("safescale label list")
	require.Nil(t, err)
	result, err := helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) == 0)

	fmt.Println("Inspecting non-existent Label")
	out, err = helpers.GetOutput("safescale label inspect " + names.Labels[0])
	require.NotNil(t, err)

	fmt.Println("Creating Label " + names.Labels[0])
	out, err = helpers.GetOutput("safescale label create --value labelvalue " + names.Labels[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) == 1)

	out, err = helpers.GetOutput("safescale label create " + names.Labels[0])
	_ = out
	require.NotNil(t, err)

	out, err = helpers.GetOutput("safescale label list")
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) == 0)

	out, err = helpers.GetOutput("safescale label inspect " + names.Labels[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) == 1)
	require.True(t, result[0]["default_value"] == "labelvalue")

	time.Sleep(temporal.DefaultDelay())

	fmt.Println("Binding Label to Host with default value")
	out, err = helpers.GetOutput("safescale host label bind " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host label bind " + "gw-" + names.Networks[0] + " " + names.Tags[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host label list " + "gw-" + names.Networks[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) == 1)

	fmt.Println("Updating value of Label for Host")
	out, err = helpers.GetOutput("safescale host label update --value newvalue " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	_ = out
	require.Nil(t, err)
	out, err = helpers.GetOutput("safescale host label inspect " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) >= 0)
	require.True(t, result[0]["value"] == "newvalue")

	fmt.Println("Resetting value of Label for Host")
	out, err = helpers.GetOutput("safescale host label reset " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host label inspect " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) >= 0)
	require.True(t, result[0]["value"] == "labelvalue")

	fmt.Println("deleting still bound Label")
	out, err = helpers.GetOutput("safescale label delete " + names.Labels[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "Label still bound to hosts"))

	fmt.Println("Unbinding Label from Host")
	out, err = helpers.GetOutput("safescale host Label unbind " + "gw-" + names.Networks[0] + " " + names.Tags[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("binding Label to Host with other value")
	out, err = helpers.GetOutput("safescale host label bind --value differentvalue" + "gw-" + names.Networks[0] + " " + names.Labels[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host label list " + "gw-" + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host label inspect " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) >= 0)
	require.True(t, result[0]["value"] == "differentvalue")

	fmt.Println("unbinding Label from Host")
	out, err = helpers.GetOutput("safescale host Label unbind " + "gw-" + names.Networks[0] + " " + names.Tags[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("Deleting Label" + names.Labels[0])
	out, err = helpers.GetOutput("safescale label delete " + names.Labels[0])
	_ = out
	require.Nil(t, err)

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale tag delete " + names.Labels[0])
	_ = out
	require.NotNil(t, err)
}

func TagBase(t *testing.T) {
	names := helpers.GetNames("TagBase", 0, 1, 1, 1, 1, 0, 0, 1)
	names.TearDown()
	defer names.TearDown()

	fmt.Println("Creating network " + names.Networks[0])
	out, err := helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.43.0/24")
	_ = out
	require.Nil(t, err)

	fmt.Println("Listing Tags")
	out, err = helpers.GetOutput("safescale tag list")
	require.Nil(t, err)
	result, err := helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) == 0)

	fmt.Println("Creating Tag " + names.Tags[0])
	out, err = helpers.GetOutput("safescale tag create " + names.Tags[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) == 1)

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale tag create " + names.Tags[0])
	_ = out
	require.NotNil(t, err)

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale host tag add " + "gw-" + names.Networks[0] + " " + names.Tags[0])
	require.Nil(t, err)
	_ = out

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale host tag add " + "gw-" + names.Networks[0] + " " + names.Tags[0])
	require.Nil(t, err)
	_ = out

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale host tag list " + "gw-" + names.Networks[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) == 1)

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale tag delete " + names.Tags[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "tag still bound to hosts"))

	out, err = helpers.GetOutput("safescale host tag unbind " + "gw-" + names.Networks[0] + " " + names.Tags[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host tag list " + "gw-" + names.Networks[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.True(t, len(result) == 1)

	out, err = helpers.GetOutput("safescale tag delete " + names.Tags[0])
	_ = out
	require.Nil(t, err)

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale tag delete " + names.Tags[0])
	_ = out
	require.NotNil(t, err)
}

func TagIsNotLabel(t *testing.T) {
	names := helpers.GetNames("TagIsNotLabel", 0, 0, 0, 0, 0, 0, 1, 1)
	names.TearDown()
	defer names.TearDown()

	fmt.Println("Create Tag " + names.Tags[0])
	out, err := helpers.GetOutput("safescale tag create " + names.Tags[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("creating Label " + names.Labels[0])
	out, err = helpers.GetOutput("safescale label create " + names.Labels[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("inspecting Tag as if it is a Label")
	out, err = helpers.GetOutput("safescale label inspect " + names.Tags[0])
	_ = out
	require.NotNil(t, err)

	fmt.Println("inspecting Label as if it is a Tag")
	out, err = helpers.GetOutput("safescale tag inspect " + names.Labels[0])
	_ = out
	require.NotNil(t, err)

	fmt.Println("deleting Label as if it is a Tag")
	out, err = helpers.GetOutput("safescale label delete " + names.Tags[0])
	_ = out
	require.NotNil(t, err)

	fmt.Println("deleting Tag as if it is a Label")
	out, err = helpers.GetOutput("safescale tag delete " + names.Labels[0])
	_ = out
	require.NotNil(t, err)

}

func init() {
	helpers.InSection("labels").
		AddScenario(TagBase).
		AddScenario(LabelBase).
		AddScenario(TagIsNotLabel)
}
