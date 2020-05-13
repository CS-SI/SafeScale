package main

import (
	"testing"

	"github.com/CS-SI/SafeScale/integrationtests"
	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Test_Docker(t *testing.T) {
	integrationtests.Docker(t, providers.AWS)
}

func Test_DockerNotGateway(t *testing.T) {
	integrationtests.DockerNotGateway(t, providers.AWS)
}

func Test_DockerCompose(t *testing.T) {
	integrationtests.DockerCompose(t, providers.AWS)
}

func Test_RemoteDesktop(t *testing.T) {
	integrationtests.RemoteDesktop(t, providers.AWS)
}

func Test_ReverseProxy(t *testing.T) {
	integrationtests.ReverseProxy(t, providers.AWS)
}

func Test_Metricbeat(t *testing.T) {
	integrationtests.Metricbeat(t, providers.AWS)
}

func Test_Filebeat(t *testing.T) {
	integrationtests.Filebeat(t, providers.AWS)
}

func Test_NvidiaDocker(t *testing.T) {
	integrationtests.NvidiaDocker(t, providers.AWS)
}

func Test_ProxyCacheClient(t *testing.T) {
	integrationtests.ProxyCacheClient(t, providers.AWS)
}

func Test_ProxyCacheServer(t *testing.T) {
	integrationtests.ProxyCacheServer(t, providers.AWS)
}
