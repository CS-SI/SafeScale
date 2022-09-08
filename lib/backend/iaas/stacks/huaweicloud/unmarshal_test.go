package huaweicloud

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/stretchr/testify/require"
)

func Test_recoverImageInfo(t *testing.T) {
	var img images.Image

	data, err := os.ReadFile("./dump-img.json")
	if err != nil {
		t.Error(err)
	}

	err = json.Unmarshal(data, &img)
	if err != nil {
		t.Error(err)
	}

	type thing = map[string]interface{}

	properties := img.Properties
	r := properties["Properties"].(thing)["image"].(thing)["minRam"].(float64)
	d := properties["Properties"].(thing)["image"].(thing)["minDisk"].(float64)
	id := properties["Properties"].(thing)["image"].(thing)["id"].(string)
	name := properties["Properties"].(thing)["image"].(thing)["name"].(string)

	require.EqualValues(t, float64(1024), r)
	require.EqualValues(t, float64(40), d)
	require.EqualValues(t, "0249222b-c9be-419b-a953-f47e91c3fc81", id)
	require.EqualValues(t, "OBS Ubuntu 18.04", name)
}
