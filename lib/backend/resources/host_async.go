//go:build tunnel
// +build tunnel

package resources

import (
	"os"

	"github.com/sirupsen/logrus"
)

func getDefaultConnectorType() (string, error) {
	if choice := os.Getenv("SAFESCALE_DEFAULT_SSH"); choice != "" {
		switch choice {
		case "cli":
			return "cli", nil
		case "lib":
			return "lib", nil
		default:
			logrus.Debugf("unexpected SAFESCALE_DEFAULT_SSH: %s, using lib instead", choice)
			return "lib", nil
		}
	}

	return "lib", nil
}
