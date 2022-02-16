package main

import (
	"testing"

	"github.com/CS-SI/SafeScale/v21/integrationtests"
	"github.com/CS-SI/SafeScale/v21/integrationtests/enums/providers"
)

func Test_ClusterK8S(t *testing.T) {
	integrationtests.ClusterK8S(t, providers.CLOUDFERRO)
}

func Test_ClusterSwarm(t *testing.T) {
	integrationtests.ClusterSwarm(t, providers.CLOUDFERRO)
}
