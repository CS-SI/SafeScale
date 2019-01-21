package main

import (
	"testing"

	"github.com/CS-SI/SafeScale/integration_tests"
	"github.com/CS-SI/SafeScale/integration_tests/enums/Providers"
)

func Test_Docker(t *testing.T) {
	integration_tests.Docker(t, Providers.OVH)
}

func Test_DockerNotGateway(t *testing.T) {
	integration_tests.DockerNotGateway(t, Providers.OVH)
}

func Test_DockerCompose(t *testing.T) {
	integration_tests.DockerCompose(t, Providers.OVH)
}

func Test_RemoteDesktop(t *testing.T) {
	integration_tests.RemoteDesktop(t, Providers.OVH)
}

func Test_ReverseProxy(t *testing.T) {
	integration_tests.ReverseProxy(t, Providers.OVH)
}
