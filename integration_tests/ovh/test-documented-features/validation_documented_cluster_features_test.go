package main

import (
	"github.com/CS-SI/SafeScale/integration_tests"
	"github.com/CS-SI/SafeScale/integration_tests/enums/Providers"
	"testing"
)

func Test_ApacheIgnite(t *testing.T) {
	integration_tests.ApacheIgnite(t, Providers.OVH)
}

func Test_Helm(t *testing.T) {
	integration_tests.Helm(t, Providers.OVH)
}

func Test_Kubernetes(t *testing.T) {
	integration_tests.Kubernetes(t, Providers.OVH)
}

func Test_Spark(t *testing.T) {
	integration_tests.Spark(t, Providers.OVH)
}
