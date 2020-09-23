package integrationtests

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/integrationtests/enums/providers"
)

func Docker(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := GetNames("Docker", 0, 0, 0, 0, 1, 0)
	names.TearDown()
	defer names.TearDown()

	_, err := GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.100.0/24")
	require.Nil(t, err)

	out, err := GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, " user"))

	out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " docker")
	require.True(t, strings.Contains(out, "not found on host"))

	out, err = GetOutput("safescale host add-feature gw-" + names.Networks[0] + " docker")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"docker ps\"")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " docker")
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale host delete-feature gw-" + names.Networks[0] + " docker")
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " docker")
	require.True(t, strings.Contains(out, "not found on host"))

	out, err = GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"docker ps\"")
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func DockerNotGateway(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := GetNames("DockerNotGateway", 0, 0, 0, 1, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.101.0/24")
	require.Nil(t, err)

	out, err = GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"uptime\"")
	require.True(t, strings.Contains(out, " user"))

	out, err = GetOutput("safescale host create " + names.Hosts[0] + " --net " + names.Networks[0])
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale host check-feature " + names.Hosts[0] + " docker")
	require.True(t, strings.Contains(out, "not found on host"))

	out, err = GetOutput("safescale host add-feature " + names.Hosts[0] + " docker")
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale ssh run " + names.Hosts[0] + " -c \"docker ps\"")
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = GetOutput("safescale host check-feature " + names.Hosts[0] + " docker")
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale host delete-feature " + names.Hosts[0] + " docker")
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale host check-feature " + names.Hosts[0] + " docker")
	require.True(t, strings.Contains(out, "not found on host"))

	out, err = GetOutput("safescale ssh run " + names.Hosts[0] + " -c \"docker ps\"")
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func RemoteDesktop(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := GetNames("RemoteDesktop", 0, 0, 0, 1, 1, 0)
	names.TearDown()
	defer names.TearDown()

	_, err := GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.103.0/24")
	require.Nil(t, err)

	out, err := GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)
	host := HostInfo{}
	_ = json.Unmarshal([]byte(out), &host)

	out, err = GetOutput("safescale host check-feature --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	require.True(t, strings.Contains(out, "not found on host"))

	out, err = GetOutput("safescale host add-feature --skip-proxy --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	require.True(t, strings.Contains(out, "success"))

	// TODO: try to connect to the host through guacamole?
	out, err = GetOutput("wget " + host.PublicIP + ":9080/guacamole")
	fmt.Println(out)

	out, err = GetOutput("safescale host check-feature --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale host delete-feature --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	fmt.Println(out)
	fmt.Println(err)
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale host check-feature --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	require.True(t, strings.Contains(out, "not found on host"))

	out, err = GetOutput("wget " + host.PublicIP + ":9080/guacamole")
	fmt.Print(out)
}

func ReverseProxy(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := GetNames("ReverseProxy", 0, 0, 0, 0, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.104.0/24")
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " kong")
	require.True(t, strings.Contains(out, "not found on host"))

	out, err = GetOutput("safescale host add-feature gw-" + names.Networks[0] + " kong")
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"curl -Ssl -I -k https://localhost:8444/ 2>&1 | grep \\\"HTTP/1.1 200 OK\\\"\"")
	fmt.Print(out)
	require.Nil(t, err)

	out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " kong")
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale host delete-feature gw-" + names.Networks[0] + " kong")
	require.True(t, strings.Contains(out, "success"))

	out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " kong")
	require.True(t, strings.Contains(out, "not found on host"))

	out, err = GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"curl -Ssl -I -k https://localhost:8444/ 2>&1 | grep \\\"HTTP/1.1 200 OK\\\"\"")
	fmt.Print(out)
	require.Nil(t, err)
}

func Installers(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := GetNames("Installers", 0, 0, 0, 0, 1, 0)
	names.TearDown()
	defer names.TearDown()

	_, err := GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.110.0/24")
	require.Nil(t, err)

	out, err := GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, " user"))

	var feats []string
	feats = append(feats, "metricbeat")
	feats = append(feats, "ansible")
	feats = append(feats, "filebeat")
	feats = append(feats, "heartbeat")
	feats = append(feats, "docker")
	feats = append(feats, "elassandra")
	feats = append(feats, "elastalert")
	feats = append(feats, "elasticsearch")
	feats = append(feats, "kibana")
	feats = append(feats, "logstash")
	feats = append(feats, "ntpserver")
	feats = append(feats, "ntpclient")
	feats = append(feats, "packetbeat")
	feats = append(feats, "proxycache-server")
	feats = append(feats, "proxycache-client")
	feats = append(feats, "mpich-build")

	for _, feat := range feats {
		fmt.Printf("Working on feature %s\n", feat)
		out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "not found on host") {
			t.Fail()
		}

		out, err = GetOutput("safescale host add-feature gw-" + names.Networks[0] + " " + feat)
		fmt.Println(out)
		if !strings.Contains(out, "success") {
			t.Fail()
		}

		out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "not found on host") {
			t.Fail()
		}

		out, err = GetOutput("safescale host delete-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "success") {
			t.Fail()
		}

		out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "not found on host") {
			t.Fail()
		}
	}
}

func Heartbeat(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := GetNames("beats", 0, 0, 0, 0, 1, 0)
	names.TearDown()
	defer names.TearDown()

	_, err := GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.111.0/24")
	require.Nil(t, err)

	out, err := GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, " user"))

	var feats []string
	feats = append(feats, "heartbeat")

	for _, feat := range feats {
		fmt.Printf("Working on feature %s\n", feat)
		out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "not found on host") {
			t.Fail()
		}

		out, err = GetOutput("safescale host add-feature gw-" + names.Networks[0] + " " + feat)
		fmt.Println(out)
		if !strings.Contains(out, "success") {
			t.Fail()
		}

		out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "not found on host") {
			t.Fail()
		}

		out, err = GetOutput("safescale host delete-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "success") {
			t.Fail()
		}

		out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "not found on host") {
			t.Fail()
		}
	}
}

func Metricbeat(t *testing.T, provider providers.Enum) {
	// TODO: Implement integration test
}

func Filebeat(t *testing.T, provider providers.Enum) {
	// TODO: Implement integration test
}

func NvidiaDocker(t *testing.T, provider providers.Enum) {
	// TODO: Implement integration test
}

func ProxyCacheClient(t *testing.T, provider providers.Enum) {
	// TODO: Implement integration test
}

func ProxyCacheServer(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := GetNames("proxycache", 0, 0, 0, 0, 1, 0)
	names.TearDown()
	defer names.TearDown()

	_, err := GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.111.0/24")
	require.Nil(t, err)

	out, err := GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, " user"))

	var feats []string
	feats = append(feats, "proxycache-server")

	for _, feat := range feats {
		fmt.Printf("Working on feature %s\n", feat)
		out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "not found on host") {
			t.Fail()
		}

		out, err = GetOutput("safescale host add-feature gw-" + names.Networks[0] + " " + feat)
		fmt.Println(out)
		if !strings.Contains(out, "success") {
			t.Fail()
		}

		out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "not found on host") {
			t.Fail()
		}

		out, err = GetOutput("safescale host delete-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "success") {
			t.Fail()
		}

		out, err = GetOutput("safescale host check-feature gw-" + names.Networks[0] + " " + feat)
		if !strings.Contains(out, "not found on host") {
			t.Fail()
		}
	}
}

func ApacheIgnite(t *testing.T, provider providers.Enum) {
	// TODO: Implement integration test
}

func Helm(t *testing.T, provider providers.Enum) {
	// TODO: Implement integration test
}

func Kubernetes(t *testing.T, provider providers.Enum) {
	// TODO: Implement integration test
}

func Spark(t *testing.T, provider providers.Enum) {
	// TODO: Implement integration test
}
