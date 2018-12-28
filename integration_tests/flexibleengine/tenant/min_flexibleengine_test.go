package tenant

import (
	"testing"

	"github.com/CS-SI/SafeScale/integration_tests"
	"github.com/CS-SI/SafeScale/integration_tests/enums/Providers"
)

func Test_Env_Setup(t *testing.T) {
	integration_tests.EnvSetup(t, Providers.FLEXIBLEENGINE)
}

func Test_Setup(t *testing.T) {
	integration_tests.Setup(t, Providers.FLEXIBLEENGINE)
}
