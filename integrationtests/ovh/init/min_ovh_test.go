package init

import (
	"testing"

	"github.com/CS-SI/SafeScale/v21/integrationtests"
	"github.com/CS-SI/SafeScale/v21/integrationtests/enums/providers"
)

func Test_Env_Setup(t *testing.T) {
	integrationtests.EnvSetup(t, providers.OVH)
}
