package main

import (
	"testing"

	"github.com/CS-SI/SafeScale/integrationtests"
	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Test_Docker(t *testing.T) {
	integrationtests.Docker(t, providers.OVH)
}

func Test_DockerNotGateway(t *testing.T) {
	integrationtests.DockerNotGateway(t, providers.OVH)
}

func Test_RemoteDesktop(t *testing.T) {
	integrationtests.RemoteDesktop(t, providers.OVH)
}

func Test_Installs(t *testing.T) {
	// integrationtests.Installers(t, providers.OVH)
}

func Test_Heartbeat(t *testing.T) {
	integrationtests.Heartbeat(t, providers.OVH)
}

func Test_Proxy(t *testing.T) {
	integrationtests.ProxyCacheServer(t, providers.OVH)
}
