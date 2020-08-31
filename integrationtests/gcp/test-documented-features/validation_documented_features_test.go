package main

import (
    "testing"

    "github.com/CS-SI/SafeScale/integrationtests"
    "github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Test_Docker(t *testing.T) {
    integrationtests.Docker(t, providers.GCP)
}

func Test_DockerNotGateway(t *testing.T) {
    integrationtests.DockerNotGateway(t, providers.GCP)
}

func Test_RemoteDesktop(t *testing.T) {
    integrationtests.RemoteDesktop(t, providers.GCP)
}

func Test_ReverseProxy(t *testing.T) {
    integrationtests.ReverseProxy(t, providers.GCP)
}

func Test_Metricbeat(t *testing.T) {
    integrationtests.Metricbeat(t, providers.GCP)
}

func Test_Filebeat(t *testing.T) {
    integrationtests.Filebeat(t, providers.GCP)
}

func Test_NvidiaDocker(t *testing.T) {
    integrationtests.NvidiaDocker(t, providers.GCP)
}

func Test_ProxyCacheClient(t *testing.T) {
    integrationtests.ProxyCacheClient(t, providers.GCP)
}

func Test_ProxyCacheServer(t *testing.T) {
    integrationtests.ProxyCacheServer(t, providers.GCP)
}
