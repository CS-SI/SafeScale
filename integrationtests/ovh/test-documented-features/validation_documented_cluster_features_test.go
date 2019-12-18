package main

import (
	"github.com/CS-SI/SafeScale/integrationtests"
	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
	"testing"
)

func Test_ApacheIgnite(t *testing.T) {
	integrationtests.ApacheIgnite(t, providers.OVH)
}

func Test_Helm(t *testing.T) {
	integrationtests.Helm(t, providers.OVH)
}

func Test_Kubernetes(t *testing.T) {
	integrationtests.Kubernetes(t, providers.OVH)
}

func Test_Spark(t *testing.T) {
	integrationtests.Spark(t, providers.OVH)
}
