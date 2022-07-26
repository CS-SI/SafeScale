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

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

func LabelBase(t *testing.T) {
	names := helpers.GetNames("LabelBase", 0, 0, 0, 0, 1, 0, 1, 0)
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
	require.NotNil(t, err)
	require.Nil(t, result)

	fmt.Println("Inspecting non-existent Label")
	out, err = helpers.GetOutput("safescale label inspect " + names.Labels[0])
	require.NotNil(t, err)

	fmt.Println("Creating Label " + names.Labels[0] + " with value 'labelvalue'")
	out, err = helpers.GetOutput("safescale label create --value labelvalue " + names.Labels[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.NotNil(t, result)
	require.True(t, result.(map[string]interface{})["name"].(string) == names.Labels[0])

	fmt.Println("Creating same Label " + names.Labels[0] + " with other value (none)")
	out, err = helpers.GetOutput("safescale label create " + names.Labels[0])
	_ = out
	require.NotNil(t, err)

	out, err = helpers.GetOutput("safescale label list")
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.NotNil(t, result)
	require.True(t, len(result.([]interface{})) > 0)

	fmt.Println("Inspecting Label " + names.Labels[0])
	out, err = helpers.GetOutput("safescale label inspect " + names.Labels[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.NotNil(t, result)
	require.True(t, result.(map[string]interface{})["default_value"] == "labelvalue")

	time.Sleep(temporal.DefaultDelay())

	fmt.Println("Binding Label to Host with default value")
	out, err = helpers.GetOutput("safescale host label bind " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host label bind " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host label list " + "gw-" + names.Networks[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.NotNil(t, result)
	require.True(t, len(result.([]interface{})) == 1)

	out, err = helpers.GetOutput("safescale host label inspect " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.NotNil(t, result)
	t.Logf("Received: %s, and result was %s", out, spew.Sdump(result))
	rmap := result.(map[string]interface{})
	require.True(t, rmap["value"].(string) == "labelvalue")

	fmt.Println("Checking host inspect display Labels...")
	out, err = helpers.GetOutput("safescale host inspect " + "gw-" + names.Networks[0])
	require.Nil(t, err)
	t.Logf("Received: %s", out)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.NotNil(t, result)
	require.True(t, len(result.(map[string]interface{})["labels"].([]interface{})) > 0)
	// FIXME: check content of Label from safescale host inspect
	// require.True(t, result.(map[string]interface{})["labels"].([]map[string]interface{})[0][""] > 0))

	fmt.Println("Updating value of Label for Host")
	out, err = helpers.GetOutput("safescale host label update --value newvalue " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host label inspect " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.NotNil(t, result)
	rmap = result.(map[string]interface{})
	require.True(t, rmap["value"].(string) == "newvalue")

	fmt.Println("Resetting value of Label for Host")
	out, err = helpers.GetOutput("safescale host label reset " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host label inspect " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.NotNil(t, result)
	rmap = result.(map[string]interface{})
	require.True(t, rmap["value"].(string) == "labelvalue")

	fmt.Println("deleting still bound Label")
	out, err = helpers.GetOutput("safescale label delete " + names.Labels[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(strings.ToLower(out), "still bound to hosts"))

	fmt.Println("Unbinding Label from Host")
	out, err = helpers.GetOutput("safescale host label unbind " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("binding Label to Host with other value")
	out, err = helpers.GetOutput("safescale host label bind --value differentvalue " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host label list " + "gw-" + names.Networks[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host label inspect " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.NotNil(t, result)
	rmap = result.(map[string]interface{})
	require.True(t, rmap["value"].(string) == "differentvalue")

	fmt.Println("unbinding Label from Host")
	out, err = helpers.GetOutput("safescale host label unbind " + "gw-" + names.Networks[0] + " " + names.Labels[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("Deleting Label" + names.Labels[0])
	out, err = helpers.GetOutput("safescale label delete " + names.Labels[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale tag delete " + names.Labels[0])
	_ = out
	require.NotNil(t, err)
}

func TagBase(t *testing.T) {
	names := helpers.GetNames("TagBase", 0, 0, 0, 0, 1, 0, 0, 1)
	names.TearDown()
	defer names.TearDown()

	fmt.Println("Listing Tags")
	out, err := helpers.GetOutput("safescale tag list")
	require.Nil(t, err)
	result, err := helpers.ExtractResult(out)
	require.NotNil(t, err)
	require.Nil(t, result)

	fmt.Println("Creating Tag " + names.Tags[0])
	out, err = helpers.GetOutput("safescale tag create " + names.Tags[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.NotNil(t, result)
	require.True(t, result.(map[string]interface{})["name"] == names.Tags[0])

	out, err = helpers.GetOutput("safescale tag create " + names.Tags[0])
	_ = out
	require.NotNil(t, err)

	fmt.Println("Creating network " + names.Networks[0])
	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.43.0/24")
	_ = out
	require.Nil(t, err)

	fmt.Printf("Binding tag %s to host gw-%s\n", names.Tags[0], names.Networks[0])
	out, err = helpers.GetOutput("safescale host tag bind " + "gw-" + names.Networks[0] + " " + names.Tags[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host tag bind " + "gw-" + names.Networks[0] + " " + names.Tags[0])
	_ = out
	require.Nil(t, err)

	fmt.Printf("Listing tags of host gw-%s\n", names.Networks[0])
	out, err = helpers.GetOutput("safescale host tag list " + "gw-" + names.Networks[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.Nil(t, err)
	require.NotNil(t, result)
	require.NotNil(t, len(result.([]interface{})) > 0)

	fmt.Printf("Deleting tag %s (should fail because stil bound)\n", names.Tags[0])
	out, err = helpers.GetOutput("safescale tag delete " + names.Tags[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(strings.ToLower(out), "still bound to hosts"))

	fmt.Printf("Unbinding tag %s from host gw-%s\n", names.Tags[0], names.Networks[0])
	out, err = helpers.GetOutput("safescale host tag unbind " + "gw-" + names.Networks[0] + " " + names.Tags[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host tag list " + "gw-" + names.Networks[0])
	require.Nil(t, err)
	result, err = helpers.ExtractResult(out)
	require.NotNil(t, err)
	require.Nil(t, result)

	out, err = helpers.GetOutput("safescale tag delete " + names.Tags[0])
	_ = out
	require.Nil(t, err)

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
	require.Nil(t, err)

	fmt.Println("deleting Tag as if it is a Label")
	out, err = helpers.GetOutput("safescale tag delete " + names.Labels[0])
	_ = out
	require.Nil(t, err)
}

func init() {
}
