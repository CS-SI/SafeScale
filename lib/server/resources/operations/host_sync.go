package operations

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/sirupsen/logrus"
)

func getCommand(file string) string {
	command := fmt.Sprintf("sudo bash %s; exit $?", file)
	logrus.Debugf("running '%s'", command)
	return command
}

func getPhase2Timeout(timings temporal.Timings) time.Duration {
	return timings.HostOperationTimeout()
}

func getPhase4Timeout(timings temporal.Timings) time.Duration {
	waitingTime := temporal.MaxTimeout(4*time.Minute, timings.HostCreationTimeout())
	return waitingTime
}

func inBackground() bool {
	return false
}
