package test

import (
	"testing"

	"github.com/CS-SI/SafeScale/integration_tests"
	"github.com/CS-SI/SafeScale/integration_tests/enums/Providers"
)

func Test_Basic(t *testing.T) {
	integration_tests.Basic(t, Providers.CLOUDFERRO)
}
func Test_ReadyToSsh(t *testing.T) {
	integration_tests.ReadyToSsh(t, Providers.CLOUDFERRO)
}

func Test_ShareError(t *testing.T) {
	integration_tests.ShareError(t, Providers.CLOUDFERRO)
}

func Test_VolumeError(t *testing.T) {
	integration_tests.VolumeError(t, Providers.CLOUDFERRO)
}

func Test_StopStart(t *testing.T) {
	integration_tests.StopStart(t, Providers.CLOUDFERRO)
}

func Test_DeleteVolumeMounted(t *testing.T) {
	integration_tests.DeleteVolumeMounted(t, Providers.CLOUDFERRO)
}

func Test_UntilShare(t *testing.T) {
	integration_tests.UntilShare(t, Providers.CLOUDFERRO)
}

func Test_UntilVolume(t *testing.T) {
	integration_tests.UntilVolume(t, Providers.CLOUDFERRO)
}