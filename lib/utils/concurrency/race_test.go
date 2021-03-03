// +build race

package concurrency

import (
	"fmt"
	"io/ioutil"
	"os"
	_ "runtime/race"
	"strings"
	"testing"
)

func races() {
	wait := make(chan struct{})
	n := 0
	go func() {
		n++ // read, increment, write
		close(wait)
	}()
	n++ // conflicting access
	<-wait
}

func TestRace(t *testing.T) {
	raceParam := checkRacingParameters()
	if !raceParam {
		t.Errorf("This test MUST run with GORACE env variables")
		t.FailNow()
	}

	// Remove previous race checks
	files, _ := ioutil.ReadDir("./")
	for _, f := range files {
		if strings.Contains(f.Name(), "races") {
			_ = os.Remove(f.Name())
		}
	}

	races()

	there := false
	files, _ = ioutil.ReadDir("./")
	for _, f := range files {
		if strings.Contains(f.Name(), "races") {
			fmt.Println(f.Name())
			there = true
			break
		}
	}

	if !there {
		t.Errorf("This test MUST use -race flag")
		t.FailNow()
	}

	t.SkipNow()
}

func checkRacingParameters() bool {
	there := false
	for _, env := range os.Environ() {
		if strings.Contains(env, "GORACE") {
			there = true
			break
		}
	}
	return there
}
