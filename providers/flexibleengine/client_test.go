package flexibleengine_test

import (
	"testing"

	"github.com/SafeScale/providers"

	"github.com/SafeScale/providers/flexibleengine"
	"github.com/SafeScale/providers/tests"
)

var tester *tests.ClientTester
var client *flexibleengine.Client

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

func getClient() *flexibleengine.Client {
	if client == nil {

		service, _ := providers.GetService("flexibleengine")
		client = service.ClientAPI.(*flexibleengine.Client)

	}
	return client
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
