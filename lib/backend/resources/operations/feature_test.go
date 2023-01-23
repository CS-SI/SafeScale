package operations

import (
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func minioIsRunning() (bool, error) {
	value, ok := os.LookupEnv("MINIO_HEALTH_ENDPOINT")
	if !ok {
		// putting in place previous env variable is responsibility of the script running the tests (or DOCKER env, or GitHub Action, etc.) or needs to be tailored by the developer to fit dev environment
		value = "http://localhost:9000/minio/health/live"
	}

	// See https://docs.min.io/minio/baremetal/monitoring/healthcheck-probe.html
	resp, err := http.Get(value) // nolint
	if err != nil {
		return false, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	good := false

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("failure: it seems something went wrong starting minio in: %s", value)
	}

	for k, v := range resp.Header {
		if k == "Server" {
			for _, vals := range v {
				if strings.Contains(vals, "MinIO") {
					good = true
					break
				}
			}
		}
	}

	if !good {
		return false, fmt.Errorf("failure: it seems minio is not running in: %s", value)
	}

	return true, nil
}

type cloak struct { // FIXME: OPP The one problem
	Hosts    string
	Gateways string
	Masters  string
	Nodes    string
}

func TestNewEmbeddedFeature(t *testing.T) {
	itIs, err := minioIsRunning()
	if !itIs {
		t.Skip()
	}
	if err != nil {
		t.Error(err)
	}

	// FIXME: This test requires minio check and also the debug flag
	ol, err := objectstorage.NewLocation(objectstorage.Config{
		Type:        "s3",
		EnvAuth:     false,
		AuthVersion: 0,
		Endpoint:    "http://192.168.1.99:9000",
		User:        "admin",
		SecretKey:   "password",
		BucketName:  "bushido",
		Direct:      true,
	})
	if err != nil {
		t.Skip()
	}
	ok, err := ol.CreateBucket(context.Background(), "bushido")
	if err != nil {
		ok, err = ol.InspectBucket(context.Background(), "bushido")
		if err != nil {
			t.Error(err)
		}
	}

	sm := &minService{
		loc: ol,
		aob: ok,
	}

	efe, err := NewEmbeddedFeature(context.Background(), sm, "docker")
	require.Nil(t, err)
	require.NotNil(t, efe)

	shit, err := efe.PrepareParameters(context.Background(), map[string]interface{}{}, nil)
	require.Nil(t, err)
	require.NotNil(t, shit)

	boo := efe.Specs().GetString("feature.install.bash.add.pace")
	require.NotEmpty(t, boo)

	foo := efe.Specs().GetStringMap("feature.install.bash.add.steps")
	require.NotEmpty(t, foo)

	disjoint := foo["docker-compose"].(map[string]interface{})["targets"]
	require.NotEmpty(t, disjoint)

	var input cloak
	err = mapstructure.Decode(disjoint, &input)
	require.Nil(t, err)

	var merged []string
	merged = append(merged, "\n")

	for _, v := range strings.Split(boo, ",") {
		t.Logf("Is this entertaining: %s", v)
		sk := foo[v].(map[string]interface{})
		choices := strings.ReplaceAll(sk["run"].(string), "sfExit\n", "\n")
		merged = append(merged, choices)
	}

	merged = append(merged, "sfExit\n")

	result := strings.Join(merged, "\n")
	t.Log(result)
}

func TestNewEmbeddedFeatureFunction(t *testing.T) {
	itIs, err := minioIsRunning()
	if !itIs {
		t.Skip()
	}
	if err != nil {
		t.Error(err)
	}

	ol, err := objectstorage.NewLocation(objectstorage.Config{
		Type:        "s3",
		EnvAuth:     false,
		AuthVersion: 0,
		Endpoint:    "http://192.168.1.99:9000",
		User:        "admin",
		SecretKey:   "password",
		BucketName:  "bushido",
		Direct:      true,
	})
	if err != nil {
		t.Skip()
	}
	ok, err := ol.CreateBucket(context.Background(), "bushido")
	if err != nil {
		ok, err = ol.InspectBucket(context.Background(), "bushido")
		if err != nil {
			t.Error(err)
		}
	}

	sm := &minService{
		loc: ol,
		aob: ok,
	}

	efe, err := NewEmbeddedFeature(context.Background(), sm, "ansible-for-cluster")
	require.Nil(t, err)
	require.NotNil(t, efe)

	res, err := RenderFeature(context.Background(), *efe)
	require.Nil(t, err)
	require.NotEmpty(t, res)
	require.Contains(t, res, "sfExit")

	t.Log(res)

}

func TestExtractFeatureParameters(t *testing.T) {
	var hell []string
	hell = append(hell, "login=wat")
	hell = append(hell, "pass=wot")
	hell = append(hell, "feat:lol=wat")
	hell = append(hell, "feat:passz=wot")

	dm, _ := ExtractFeatureParameters(hell)
	assert.Equalf(t, "wat", dm["login"], "first key failed")
	assert.Equalf(t, "wot", dm["pass"], "second key failed")
	assert.Equalf(t, "wat", dm["lol"], "3rd key failed")
	assert.Equalf(t, "wot", dm["passz"], "4th key failed")
}

func TestNewExtractFeatureParameters(t *testing.T) {
	var hell []string
	hell = append(hell, "login=wat")
	hell = append(hell, "pass=wot")
	hell = append(hell, "feat:lol=wat")
	hell = append(hell, "feat:passz=wot")

	dm, err := ExtractFeatureParameters(hell)
	assert.Nil(t, err)
	assert.Equalf(t, "wat", dm["login"], "first key failed")
	assert.Equalf(t, "wot", dm["pass"], "second key failed")
	assert.Equalf(t, "wat", dm["lol"], "3rd key failed")
	assert.Equalf(t, "wot", dm["passz"], "4th key failed")
}

func TestNewExtractFeatureParametersThatFail(t *testing.T) {
	var hell []string
	hell = append(hell, "login=wat")
	hell = append(hell, "pass=wot")
	hell = append(hell, "feat:lol=wat")
	hell = append(hell, "feat:passz=wot")
	hell = append(hell, "lostrespect")

	dm, err := ExtractFeatureParameters(hell)
	assert.NotNil(t, err)
	assert.Nil(t, dm)
}
