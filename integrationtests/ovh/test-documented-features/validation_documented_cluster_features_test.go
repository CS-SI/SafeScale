package main

import (
	"testing"

	"github.com/CS-SI/SafeScale/integrationtests"
	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Test_Helm(t *testing.T) {
	integrationtests.Helm(t, providers.OVH)
}

func Test_Kubernetes(t *testing.T) {
	integrationtests.Kubernetes(t, providers.OVH)
}
