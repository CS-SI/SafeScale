package install

import (
	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	"github.com/CS-SI/SafeScale/deploy/install/api"
)

// asyncCheckHosts ...
func asyncCheckHosts(hostIDs []string, c api.Component, v map[string]interface{}, done chan map[string]api.CheckState) {
	states := map[string]api.CheckState{}
	dones := map[string]chan api.CheckState{}
	broker := brokerclient.New()
	for _, hostID := range hostIDs {
		host, err := broker.Host.Inspect(hostID, 0)
		if err != nil {
			states[hostID] = api.CheckState{Success: false, Error: err.Error()}
			continue
		}
		d := make(chan api.CheckState)
		dones[host.Name] = d
		go func() {
			_, results, err := c.Check(NewNodeTarget(host), v)
			if err != nil {
				d <- api.CheckState{Success: false, Error: err.Error()}
			} else {
				d <- results.PrivateNodes[host.Name]
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
				d <- result.PrivateNodes[host.Name]
			}
		}()
	}

	for name := range dones {
		states[name] = <-dones[name]
	}
	done <- states
}

func asyncRemoveFromHosts(list []string, c api.Component, v map[string]interface{}, done chan map[string]error) {
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
			_, result, err := c.Remove(NewNodeTarget(host), v)
			if err != nil {
				d <- err
			} else {
				d <- result.PrivateNodes[host.Name]
			}
		}()
	}
	for name := range dones {
		states[name] = <-dones[name]
	}
	done <- states
}
