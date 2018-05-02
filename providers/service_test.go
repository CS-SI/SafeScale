package providers_test

import (
	"fmt"
	"testing"

	"github.com/SafeScale/providers/cloudwatt"

	"github.com/SafeScale/providers/ovh"

	"github.com/stretchr/testify/assert"

	"github.com/spf13/viper"

	"github.com/SafeScale/providers"
)

func TestCompare(t *testing.T) {
	s1 := providers.SimilarityScore("16.04", "ubuntu-xenial-16.04-amd64-server-20170329")
	fmt.Println(s1)
}

func TestParameters(t *testing.T) {
	p := make(map[string]interface{})
	p["String"] = "fkldkjfkdl"
	s := p["String"].(string)
	fmt.Println(s)
	s, _ = p["String2"].(string)
	fmt.Println(s)
}

func TestViper(t *testing.T) {
	viper.AddConfigPath(".")
	viper.SetConfigName("tenants")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	fmt.Println(viper.ConfigFileUsed())
	settings := viper.AllSettings()
	tenants, _ := settings["tenants"].([]interface{})
	for _, t := range tenants {
		tenant, _ := t.(map[string]interface{})
		for k, v := range tenant {
			fmt.Println(k, v)
		}
		fmt.Println("--------------------------")
	}
}

func TestLoad(t *testing.T) {
	providers.Register("ovh", &ovh.Client{})
	providers.Register("cloudwatt", &cloudwatt.Client{})
	ovh, err := providers.GetService("TestOvh")
	assert.NoError(t, err)
	imgs, err := ovh.ListImages()
	assert.NoError(t, err)
	assert.True(t, len(imgs) > 3)
	_, err = providers.GetService("TestCloudwatt")
	assert.NoError(t, err)
}
