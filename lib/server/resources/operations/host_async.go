//go:build disabled
// +build disabled

package operations

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/sirupsen/logrus"
)

func getCommand(file string) string {
	// "sudo -b bash -c 'nohup %s > /dev/null 2>&1 &'"
	command := fmt.Sprintf("sudo -b bash -c 'nohup %s > /dev/null 2>&1 &'", file)
	logrus.Debugf("running '%s'", command)
	return command
}

func getPhase2Timeout(timings temporal.Timings) time.Duration {
	return timings.ContextTimeout()
}

func getPhase4Timeout(timings temporal.Timings) time.Duration {
	return 30 * time.Second
}

func inBackground() bool {
	return true
}
