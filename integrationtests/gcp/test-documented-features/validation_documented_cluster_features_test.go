package main

import (
	"testing"

	"github.com/CS-SI/SafeScale/integrationtests"
	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Test_ApacheIgnite(t *testing.T) {
	integrationtests.ApacheIgnite(t, providers.GCP)
}

func Test_Helm(t *testing.T) {
	integrationtests.Helm(t, providers.GCP)
}

func Test_Kubernetes(t *testing.T) {
	integrationtests.Kubernetes(t, providers.GCP)
}

func Test_Spark(t *testing.T) {
	integrationtests.Spark(t, providers.GCP)
}
