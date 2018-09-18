package install

import (
	brokerclient "github.com/CS-SI/SafeScale/broker/client"
)

// asyncCheckHosts ...
func asyncCheckHosts(hostIDs []string, c *Component, v map[string]interface{}, done chan map[string]CheckState) {
	states := map[string]CheckState{}
	dones := map[string]chan CheckState{}
	broker := brokerclient.New()
	for _, hostID := range hostIDs {
		host, err := broker.Host.Inspect(hostID, 0)
		if err != nil {
			states[hostID] = CheckState{Success: false, Error: err.Error()}
			continue
		}
		d := make(chan CheckState)
		dones[host.Name] = d
		go func() {
			_, results, err := c.Check(NewNodeTarget(host), v)
			if err != nil {
				d <- CheckState{Success: false, Error: err.Error()}
			} else {
				d <- results[host.Name]
			}
		}()
	}

	for name := range dones {
		states[name] = <-dones[name]
	}
	done <- states
}

// asyncAddOnHosts installs a component on all the hosts in the list
func asyncAddOnHosts(list []string, c *Component, v map[string]interface{}, done chan map[string]stepErrors) {
	states := map[string]stepErrors{}
	dones := map[string]chan stepErrors{}
	broker := brokerclient.New()
	for _, hostID := range list {
		host, err := broker.Host.Inspect(hostID, 0)
		if err != nil {
			states[hostID] = stepErrors{"__error__": err}
			continue
		}
		d := make(chan stepErrors)
		dones[host.GetName()] = d
		go func() {
			_, results, err := c.Add(NewNodeTarget(host), v)
			if err != nil {
				d <- stepErrors{host.Name: err}
			} else {
				d <- results[host.Name]
			}
		}()
	}

	for name := range dones {
		states[name] = <-dones[name]
	}
	done <- states
}

func asyncRemoveFromHosts(list []string, c *Component, v map[string]interface{}, done chan map[string]stepErrors) {
	states := map[string]stepErrors{}
	dones := map[string]chan stepErrors{}
	broker := brokerclient.New()
	for _, hostID := range list {
		host, err := broker.Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			states[hostID] = stepErrors{"__error__": err}
			continue
		}
		d := make(chan stepErrors)
		dones[host.GetName()] = d
		go func() {
			_, results, err := c.Remove(NewNodeTarget(host), v)
			if err != nil {
				d <- stepErrors{"__error__": err}
			} else {
				d <- results.AddResults[host.Name]
			}
		}()
	}
	for name := range dones {
		states[name] = <-dones[name]
	}
	done <- states
}
