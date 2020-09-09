package main

import (
	"testing"

	"github.com/CS-SI/SafeScale/integrationtests"
	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Test_ClusterK8S(t *testing.T) {
	integrationtests.ClusterK8S(t, providers.OVH)
}

func Test_ClusterSwarm(t *testing.T) {
	integrationtests.ClusterSwarm(t, providers.OVH)
}
