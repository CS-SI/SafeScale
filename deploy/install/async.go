package install

import (
	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	"github.com/CS-SI/SafeScale/deploy/install/api"
)

// asyncCheckHosts ...
func asyncCheckHosts(hostIDs []string, c api.Component, done chan map[string]string) {
	states := map[string]string{}
	dones := map[string]chan string{}
	broker := brokerclient.New()
	for _, hostID := range hostIDs {
		host, err := broker.Host.Inspect(hostID, 0)
		if err != nil {
			states[hostID] = err.Error()
			continue
		}
		d := make(chan string)
		dones[host.GetName()] = d
		go func() {
			_, result, err := c.Check(NewNodeTarget(host))
			if err != nil {
				d <- err.Error()
			} else {
				d <- result.PrivateNodes[host.GetID()]
			}
		}()
	}

	for name := range dones {
		states[name] = <-dones[name]
	}
	done <- states
}

// asyncAddOnHosts installs a component on all the hosts in the list
func asyncAddOnHosts(list []string, c api.Component, v map[string]interface{}, done chan map[string]error) {
	states := map[string]error{}
	dones := map[string]chan error{}
	broker := brokerclient.New()
	for _, hostID := range list {
		host, err := broker.Host.Inspect(hostID, 0)
		if err != nil {
			states[hostID] = err
			continue
		}
		d := make(chan error)
		dones[host.GetName()] = d
		go func() {
			_, result, err := c.Add(NewNodeTarget(host), v)
			if err != nil {
				d <- err
			} else {
				d <- result.PrivateNodes[host.GetID()]
			}
		}()
	}

	for name := range dones {
		states[name] = <-dones[name]
	}
	done <- states
}

func asyncRemoveFromHosts(list []string, c api.Component, done chan map[string]error) {
	states := map[string]error{}
	dones := map[string]chan error{}
	broker := brokerclient.New()
	for _, hostID := range list {
		host, err := broker.Host.Inspect(hostID, brokerclient.DefaultTimeout)
		if err != nil {
			states[hostID] = err
			continue
		}
		d := make(chan error)
		dones[host.GetName()] = d
		go func() {
			_, result, err := c.Remove(NewNodeTarget(host))
			if err != nil {
				d <- err
			} else {
				d <- result.PrivateNodes[host.GetName()]
			}
		}()
	}
	for name := range dones {
		states[name] = <-dones[name]
	}
	done <- states
}
