package main

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"os/exec"
	"strings"
	"testing"
)

type HostInfo struct {
	ID         string
	Name       string
	CPU        int
	RAM        int
	Disk       int
	PUBLIC_IP  string
	PRIVATE_IP string
	State      int
	PrivateKey string
}

func isBrokerdLaunched() (bool, error) {
	cmd := "ps -ef | grep brokerd | grep -v grep"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), "brokerd"), nil
}

func canBeRun(command string) (bool, error) {
	cmd := "which " + command
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), command), nil
}

func getOutput(command string) (string, error) {
	out, err := exec.Command("bash", "-c", command).Output()
	if err != nil {
		return "", err
	}

	if strings.Contains(strings.ToUpper(string(out)), strings.ToUpper("Error")) {
		return string(out), errors.New(string(out))
	}

	return string(out), nil
}

func tearDown() {
	_, _ = getOutput("broker volume delete volumetest")
	_, _ = getOutput("broker host delete easyvm")
	_, _ = getOutput("broker host delete complexvm")
	_, _ = getOutput("broker host delete gw-easy")
	_, _ = getOutput("broker network delete easy")
}

func Test_Basic(t *testing.T) {
	defer tearDown()

	brokerd_launched, err := isBrokerdLaunched()
	if !brokerd_launched {
		fmt.Println("This requires that you launch brokerd in background and set the tenant")
		require.True(t, brokerd_launched)
	}
	require.Nil(t, err)

	in_path, err := canBeRun("broker")
	require.Nil(t, err)

	require.True(t, brokerd_launched)
	require.True(t, in_path)

	out, err := getOutput("broker tenant list")
	require.Nil(t, err)
	require.True(t, len(out) > 0)

	out, err = getOutput("broker tenant get")
	if err != nil {
		fmt.Println("This requires that you set the right tenant before launching the tests")
		require.Nil(t, err)
	}
	require.True(t, len(out) > 0)

	out, err = getOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network easy...")

	out, err = getOutput("broker network create easy")
	require.Nil(t, err)

	out, err = getOutput("broker network create easy")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "A network already exist"))

	fmt.Println("Creating VM easyVM...")

	out, err = getOutput("broker host create easyvm --public --net easy")
	require.Nil(t, err)

	out, err = getOutput("broker host create easyvm --public --net easy")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "A host already exist"))

	out, err = getOutput("broker host inspect easyvm")
	require.Nil(t, err)

	easyvm := HostInfo{}
	json.Unmarshal([]byte(out), &easyvm)

	fmt.Println("Creating VM complexvm...")

	out, err = getOutput("broker host create complexvm --public --net easy")
	require.Nil(t, err)

	out, err = getOutput("broker host create complexvm --public --net easy")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "A host already exist"))

	out, err = getOutput("broker nas list")
	require.Nil(t, err)

	fmt.Println("Creating NAS nastest...")

	out, err = getOutput("broker nas  create nastest easyvm")
	require.Nil(t, err)

	out, err = getOutput("broker nas  mount nastest complexvm")
	require.Nil(t, err)

	out, err = getOutput("broker nas list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "nastest"))

	out, err = getOutput("broker nas inspect nastest")
	require.Nil(t, err)

	require.True(t, strings.Contains(out, "nastest"))
	require.True(t, strings.Contains(out, "easyvm"))
	require.True(t, strings.Contains(out, "complexvm"))

	out, err = getOutput("broker nas  umount nastest complexvm")
	require.Nil(t, err)

	out, err = getOutput("broker nas inspect nastest")
	require.Nil(t, err)

	require.True(t, strings.Contains(out, "nastest"))
	require.True(t, strings.Contains(out, "easyvm"))
	require.False(t, strings.Contains(out, "complexvm"))

	out, err = getOutput("broker nas delete nastest ")
	require.Nil(t, err)

	out, err = getOutput("broker nas list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	out, err = getOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	fmt.Println("Creating Volume volumetest...")

	out, err = getOutput("broker volume  create volumetest")
	require.Nil(t, err)

	out, err = getOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "volumetest"))

	out, err = getOutput("broker volume  attach  volumetest easyvm ")
	require.Nil(t, err)

	out, err = getOutput("broker volume delete volumetest")
	require.NotNil(t, err)
	require.True(t, strings.Contains(err.Error(), "still attached"))

	out, err = getOutput("broker volume inspect volumetest")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, easyvm.ID))

	out, err = getOutput("broker volume  detach  volumetest easyvm ")
	require.Nil(t, err)

	out, err = getOutput("broker volume inspect volumetest")
	require.Nil(t, err)
	require.False(t, strings.Contains(out, easyvm.ID))

	out, err = getOutput("broker volume delete volumetest")
	require.Nil(t, err)

	out, err = getOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	out, err = getOutput("broker ssh run easyvm -c \"uptime\"")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = getOutput("broker host delete easyvm")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = getOutput("broker host delete complexvm")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = getOutput("broker host delete gw-easy")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = getOutput("broker network delete easy")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))
}
