package test

import (
	"testing"

	"github.com/CS-SI/SafeScale/integrationtests"
	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Test_Basic(t *testing.T) {
	integrationtests.Basic(t, providers.CLOUDFERRO)
}
func Test_ReadyToSsh(t *testing.T) {
	integrationtests.ReadyToSSH(t, providers.CLOUDFERRO)
}

func Test_ShareError(t *testing.T) {
	integrationtests.ShareError(t, providers.CLOUDFERRO)
}

func Test_VolumeError(t *testing.T) {
	integrationtests.VolumeError(t, providers.CLOUDFERRO)
}

func Test_StopStart(t *testing.T) {
	integrationtests.StopStart(t, providers.CLOUDFERRO)
}

func Test_DeleteVolumeMounted(t *testing.T) {
	integrationtests.DeleteVolumeMounted(t, providers.CLOUDFERRO)
}

func Test_UntilShare(t *testing.T) {
	integrationtests.UntilShare(t, providers.CLOUDFERRO)
}

func Test_UntilVolume(t *testing.T) {
	integrationtests.UntilVolume(t, providers.CLOUDFERRO)
}
