package main

import (
	"testing"

	"github.com/CS-SI/SafeScale/integrationtests"
	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Test_Docker(t *testing.T) {
	integrationtests.Docker(t, providers.FLEXIBLEENGINE)
}

func Test_DockerNotGateway(t *testing.T) {
	integrationtests.DockerNotGateway(t, providers.FLEXIBLEENGINE)
}

func Test_DockerCompose(t *testing.T) {
	integrationtests.DockerCompose(t, providers.FLEXIBLEENGINE)
}

func Test_RemoteDesktop(t *testing.T) {
	integrationtests.RemoteDesktop(t, providers.FLEXIBLEENGINE)
}

func Test_ReverseProxy(t *testing.T) {
	integrationtests.ReverseProxy(t, providers.FLEXIBLEENGINE)
}
