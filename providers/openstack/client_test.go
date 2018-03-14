package openstack_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/SafeScale/providers"

	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/openstack"
	"github.com/SafeScale/providers/tests"
)

var tester *tests.ClientTester
var client *openstack.Client

func getTester() *tests.ClientTester {
	if tester == nil {

		tester = &tests.ClientTester{
			Service: providers.Service{
				ClientAPI: getClient(),
			},
		}

	}
	return tester

}

func getClient() *openstack.Client {
	if client == nil {
		sf := providers.NewFactory()
		sf.RegisterClient("openstack", &openstack.Client{})
		sf.Load()

		service := sf.Services["TestOpenStack"]
		client = service.ClientAPI.(*openstack.Client)

	}
	return client
}

func Test_Template(t *testing.T) {
	client := getClient()
	//Data structure to apply to userdata.sh template
	type userData struct {
		User        string
		Key         string
		ConfIF      bool
		IsGateway   bool
		AddGateway  bool
		ResolveConf string
		GatewayIP   string
	}
	dataBuffer := bytes.NewBufferString("")
	data := userData{
		User:        api.DefaultUser,
		Key:         "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		ConfIF:      true,
		IsGateway:   true,
		AddGateway:  true,
		ResolveConf: "dskjfdshjjkdhsksdhhkjs\nsfdsfsdq\ndfsqdfqsdfq",
		GatewayIP:   "172.1.2.1",
	}
	err := client.UserDataTpl.Execute(dataBuffer, data)
	assert.Nil(t, err)
	fmt.Println(dataBuffer.String())
}
func Test_ListImages(t *testing.T) {
	getTester().ListImages(t)
}

func Test_ListVMTemplates(t *testing.T) {
	getTester().ListVMTemplates(t)
}

func Test_CreateKeyPair(t *testing.T) {
	getTester().CreateKeyPair(t)
}

func Test_GetKeyPair(t *testing.T) {
	getTester().GetKeyPair(t)
}

func Test_ListKeyPairs(t *testing.T) {
	getTester().ListKeyPairs(t)
}

func Test_Networks(t *testing.T) {
	getTester().Networks(t)
}

func Test_VMs(t *testing.T) {
	getTester().VMs(t)
}

func Test_StartStopVM(t *testing.T) {
	getTester().StartStopVM(t)
}

func Test_Volume(t *testing.T) {
	getTester().Volume(t)
}

func Test_VolumeAttachment(t *testing.T) {
	getTester().VolumeAttachment(t)
}

func Test_Containers(t *testing.T) {
	getTester().Containers(t)
}

func Test_Objects(t *testing.T) {
	getTester().Objects(t)
}
