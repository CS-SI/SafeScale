package cloudwatt_test

import (
	"testing"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/tests"
)

var tester *tests.ClientTester

func getClient() *tests.ClientTester {
	if tester == nil {
		service, _ := providers.GetService("cloudwatt")
		tester = &tests.ClientTester{
			Service: *service,
		}
	}
	return tester
}

func Test_ListImages(t *testing.T) {
	getClient().ListImages(t)
}

func Test_ListVMTemplates(t *testing.T) {
	getClient().ListVMTemplates(t)
}

func Test_CreateKeyPair(t *testing.T) {
	getClient().CreateKeyPair(t)
}

func Test_GetKeyPair(t *testing.T) {
	getClient().GetKeyPair(t)
}

func Test_ListKeyPairs(t *testing.T) {
	getClient().ListKeyPairs(t)
}

func Test_Networks(t *testing.T) {
	getClient().Networks(t)
}

func Test_VMs(t *testing.T) {
	getClient().VMs(t)
}

func Test_StartStopVM(t *testing.T) {
	getClient().StartStopVM(t)
}

func Test_Volume(t *testing.T) {
	getClient().Volume(t)
}

func Test_VolumeAttachment(t *testing.T) {
	getClient().VolumeAttachment(t)
}

func Test_Containers(t *testing.T) {
	getClient().Containers(t)
}

func Test_Objects(t *testing.T) {
	getClient().Objects(t)
}
