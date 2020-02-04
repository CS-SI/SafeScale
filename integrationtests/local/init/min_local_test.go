package init

import (
	"testing"

	"github.com/CS-SI/SafeScale/integrationtests"
	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Test_Env_Setup(t *testing.T) {
	integrationtests.EnvSetup(t, providers.LOCAL)
}
