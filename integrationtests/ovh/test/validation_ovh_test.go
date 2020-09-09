package test

import (
	"testing"

	"github.com/CS-SI/SafeScale/integrationtests"
	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Test_Basic(t *testing.T) {
	integrationtests.Basic(t, providers.OVH)
}

func Test_ReadyToSSH(t *testing.T) {
	integrationtests.ReadyToSSH(t, providers.OVH)
}

func Test_ShareError(t *testing.T) {
	integrationtests.ShareError(t, providers.OVH)
}

func Test_VolumeError(t *testing.T) {
	integrationtests.VolumeError(t, providers.OVH)
}

func Test_StopStart(t *testing.T) {
	integrationtests.StopStart(t, providers.OVH)
}

func Test_DeleteVolumeMounted(t *testing.T) {
	integrationtests.DeleteVolumeMounted(t, providers.OVH)
}

func Test_UntilShare(t *testing.T) {
	integrationtests.UntilShare(t, providers.OVH)
}

func Test_UntilVolume(t *testing.T) {
	integrationtests.UntilVolume(t, providers.OVH)
}
