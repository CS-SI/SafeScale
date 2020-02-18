package features

import (
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func gatewayFromHost(task concurrency.Task, host resources.Host) (resources.Host, error) {
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if host == nil {
		return nil, scerr.InvalidParameterError("host", "cannot be nil")
	}

	network, err := host.DefaultNetwork(task)
	if err != nil {
		return nil, err
	}

	gw, err := network.Gateway(task, true)
	if err == nil {
		_, err = gw.WaitSSHReady(task, temporal.GetConnectSSHTimeout())
	}

	if err != nil {
		gw, err = network.Gateway(task, false)
		if err == nil {
			_, err = gw.WaitSSHReady(task, temporal.GetConnectSSHTimeout())
		}
	}

	if err != nil {
		return nil, scerr.NotAvailableError("no gateway available")
	}
	return gw, nil
}
