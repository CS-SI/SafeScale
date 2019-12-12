package test

import (
	"testing"

	"github.com/CS-SI/SafeScale/integration_tests"
	"github.com/CS-SI/SafeScale/integration_tests/enums/Providers"
)

func Test_Basic(t *testing.T) {
	integration_tests.Basic(t, Providers.FLEXIBLEENGINE)
}

func Test_ReadyToSsh(t *testing.T) {
	integration_tests.ReadyToSSH(t, Providers.FLEXIBLEENGINE)
}

func Test_ShareError(t *testing.T) {
	integration_tests.ShareError(t, Providers.FLEXIBLEENGINE)
}

func Test_VolumeError(t *testing.T) {
	integration_tests.VolumeError(t, Providers.FLEXIBLEENGINE)
}

func Test_StopStart(t *testing.T) {
	integration_tests.StopStart(t, Providers.FLEXIBLEENGINE)
}

func Test_DeleteVolumeMounted(t *testing.T) {
	integration_tests.DeleteVolumeMounted(t, Providers.FLEXIBLEENGINE)
}

func Test_UntilShare(t *testing.T) {
	integration_tests.UntilShare(t, Providers.FLEXIBLEENGINE)
}

func Test_UntilVolume(t *testing.T) {
	integration_tests.UntilVolume(t, Providers.FLEXIBLEENGINE)
}
