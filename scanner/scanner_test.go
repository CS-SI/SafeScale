package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCmds(t *testing.T) {
	out, err := exec.Command("bash", "-c", "lscpu -p'CPU,CORE,SOCKET,MAXMHZ,MINMHZ' | tail -1").Output()
	assert.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(out)), ",")
	fmt.Println(len(lines))

	nbThread, err := strconv.Atoi(lines[0])
	nbThread++
	assert.NoError(t, err)
	assert.Equal(t, 8, nbThread)

	nbCore, err := strconv.Atoi(lines[1])
	nbCore++
	assert.NoError(t, err)
	assert.Equal(t, 4, nbCore)

	nbSocket, err := strconv.Atoi(lines[2])
	nbSocket++
	assert.NoError(t, err)
	assert.Equal(t, 1, nbSocket)

	fMax, err := strconv.ParseFloat(lines[3], 64)
	assert.NoError(t, err)
	assert.Equal(t, 3600.0000, fMax)

	fMin, err := strconv.ParseFloat(lines[4], 64)
	assert.NoError(t, err)
	assert.Equal(t, 800.0000, fMin)
}

func TestMain(t *testing.T) {
	Run()
}
