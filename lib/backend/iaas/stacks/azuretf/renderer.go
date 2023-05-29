package azuretf

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	_ "github.com/hashicorp/hcl/v2"
	_ "github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/hashicorp/terraform-exec/tfexec"
	tfjson "github.com/hashicorp/terraform-json"
	_ "github.com/zclconf/go-cty/cty"
	"strings"
	"text/template"
)

//go:embed templates/*
var templates embed.FS

func (s stack) ExportFromState(ctx context.Context, kind abstract.Enum, tfstate *tfjson.State, input any, hint string) (any, fail.Error) {
	switch kind {
	case abstract.ObjectStorageBucketResource:
		tfn, ok := input.(*operations.TfBucket)
		if !ok || tfn == nil {
			if hint != "" {
				return nil, fail.NewError("failed to cast input to *operations.TfBucket")
			}
		}

		var stateResources []*tfjson.StateResource

		stateResources = append(stateResources, tfstate.Values.RootModule.Resources...)
		for _, module := range tfstate.Values.RootModule.ChildModules {
			stateResources = append(stateResources, module.Resources...)
		}

		if hint != "" {
			for _, resource := range stateResources {
				if resource.Type == "azurerm_storage_container" {
					name := resource.AttributeValues["name"].(string)
					if strings.Contains(name, hint) {
						tfn.Name = resource.AttributeValues["name"].(string)
						tfn.Identity = resource.AttributeValues["id"].(string)
						tfn.StorageAccount = resource.AttributeValues["storage_account_name"].(string)

						return tfn, nil
					}
				}
			}
		} else {
			var answer []*operations.TfBucket
			for _, resource := range stateResources {
				if resource.Type == "azurerm_storage_container" {
					tfn := &operations.TfBucket{}
					tfn.Name = resource.AttributeValues["name"].(string)
					tfn.Identity = resource.AttributeValues["id"].(string)
					tfn.StorageAccount = resource.AttributeValues["storage_account_name"].(string)
					answer = append(answer, tfn)
				}
			}
			return answer, nil
		}

		return nil, fail.NotFoundError("bucket %s not found", hint)
	case abstract.NicResource:
		tfn, ok := input.(*operations.TfNic)
		if !ok || tfn == nil {
			if hint != "" {
				return nil, fail.NewError("failed to cast input to *operations.TfNic")
			}
		}

		var stateResources []*tfjson.StateResource

		stateResources = append(stateResources, tfstate.Values.RootModule.Resources...)
		for _, module := range tfstate.Values.RootModule.ChildModules {
			stateResources = append(stateResources, module.Resources...)
		}

		for _, resource := range stateResources {
			if resource.Type == "azurerm_network_interface" {
				name := resource.AttributeValues["name"].(string)
				if strings.Contains(name, hint) {
					tfn.Name = resource.AttributeValues["name"].(string)
					tfn.Identity = resource.AttributeValues["id"].(string)

					return tfn, nil
				}
			}
		}

		return nil, fail.NotFoundError("nic %s not found", hint)
	case abstract.VolumeAttachmentResource:
		tfn, ok := input.(*operations.TfVolumeAttachment)
		if !ok || tfn == nil {
			if hint != "" {
				return nil, fail.NewError("failed to cast input to *operations.TfVolumeAttachment")
			}
		}

		var stateResources []*tfjson.StateResource

		stateResources = append(stateResources, tfstate.Values.RootModule.Resources...)
		for _, module := range tfstate.Values.RootModule.ChildModules {
			stateResources = append(stateResources, module.Resources...)
		}

		if hint != "" {
			for _, resource := range stateResources {
				if resource.Type == "azurerm_virtual_machine_data_disk_attachment" {
					name := resource.Name
					if hint == name || strings.HasSuffix(name, hint) {
						tfn.Name = resource.Name
						tfn.Identity = resource.AttributeValues["id"].(string)
						tfn.AttachedHostId = resource.AttributeValues["virtual_machine_id"].(string)
						tfn.AttachedDiskId = resource.AttributeValues["managed_disk_id"].(string)

						return tfn, nil
					}
				}
			}
		} else {
			var instances []*operations.TfVolumeAttachment
			for _, resource := range stateResources {
				if resource.Type == "azurerm_virtual_machine_data_disk_attachment" {
					inst := &operations.TfVolumeAttachment{}

					inst.Name = resource.Name
					inst.Identity = resource.AttributeValues["id"].(string)
					inst.AttachedHostId = resource.AttributeValues["virtual_machine_id"].(string)
					inst.AttachedDiskId = resource.AttributeValues["managed_disk_id"].(string)

					instances = append(instances, inst)
				}
			}
			return instances, nil
		}

		return nil, fail.NotFoundError("volume attachment %s not found", hint)
	case abstract.VolumeResource:
		tfn, ok := input.(*operations.TfVolume)
		if !ok || tfn == nil {
			if hint != "" {
				return nil, fail.NewError("failed to cast input to *operations.TfVolume")
			}
		}

		var stateResources []*tfjson.StateResource

		stateResources = append(stateResources, tfstate.Values.RootModule.Resources...)
		for _, module := range tfstate.Values.RootModule.ChildModules {
			stateResources = append(stateResources, module.Resources...)
		}

		if hint != "" {
			for _, resource := range stateResources {
				if resource.Type == "azurerm_managed_disk" {
					name := resource.AttributeValues["name"].(string)
					if hint == name || name == fmt.Sprintf("disk-%s", hint) {
						tfn.Name = name
						tfn.Location = resource.AttributeValues["location"].(string)
						tfn.Identity = resource.AttributeValues["id"].(string)
						jn := resource.AttributeValues["disk_size_gb"].(json.Number)
						val, _ := jn.Int64()
						tfn.Size = int32(val)

						var ok bool
						tfn.Tags, ok = resource.AttributeValues["tags"].(map[string]string)
						if !ok {
							phase, ok := resource.AttributeValues["tags"].(map[string]any)
							if ok {
								if tfn.Tags == nil {
									tfn.Tags = make(map[string]string)
								}
								for k, v := range phase {
									tfn.Tags[k] = v.(string)
								}
							}
						}

						return tfn, nil
					}
				}
			}
		} else {
			var answer []*operations.TfVolume
			for _, resource := range stateResources {
				if resource.Type == "azurerm_managed_disk" {
					tfn := &operations.TfVolume{}
					name := resource.AttributeValues["name"].(string)
					{
						tfn.Name = name
						tfn.Location = resource.AttributeValues["location"].(string)
						tfn.Identity = resource.AttributeValues["id"].(string)
						jn := resource.AttributeValues["disk_size_gb"].(json.Number)
						val, _ := jn.Int64()
						tfn.Size = int32(val)

						var ok bool
						tfn.Tags, ok = resource.AttributeValues["tags"].(map[string]string)
						if !ok {
							phase, ok := resource.AttributeValues["tags"].(map[string]any)
							if ok {
								if tfn.Tags == nil {
									tfn.Tags = make(map[string]string)
								}
								for k, v := range phase {
									tfn.Tags[k] = v.(string)
								}
							}
						}
					}
					answer = append(answer, tfn)
				}
			}
			return answer, nil
		}

		return nil, fail.NotFoundError("volume %s not found", hint)
	case abstract.SecurityGroupResource:
		tfn, ok := input.(*operations.TfSecurityGroup)
		if !ok || tfn == nil {
			if hint != "" {
				return nil, fail.NewError("failed to cast input to *operations.TfSecurityGroup")
			}
		}

		var stateResources []*tfjson.StateResource

		stateResources = append(stateResources, tfstate.Values.RootModule.Resources...)
		for _, module := range tfstate.Values.RootModule.ChildModules {
			stateResources = append(stateResources, module.Resources...)
		}

		if hint != "" {
			for _, resource := range stateResources {
				if resource.Type == "azurerm_network_security_group" {
					name := resource.AttributeValues["name"].(string)
					if hint == name || strings.Contains(name, fmt.Sprintf("%s-%s", "NetworkSecurityGroup", hint)) {
						tfn.Location = resource.AttributeValues["location"].(string)
						tfn.Identity = resource.AttributeValues["id"].(string)
						tfn.Name = name

						var ok bool
						tfn.Tags, ok = resource.AttributeValues["tags"].(map[string]string)
						if !ok {
							phase, ok := resource.AttributeValues["tags"].(map[string]any)
							if ok {
								if tfn.Tags == nil {
									tfn.Tags = make(map[string]string)
								}
								for k, v := range phase {
									tfn.Tags[k] = v.(string)
								}
							}
						}

						maybe, ok := resource.AttributeValues["security_rule"].([]any)
						if ok {
							for _, v := range maybe {
								rule, ok := v.(map[string]any)
								if ok {
									tfn.Rules = append(tfn.Rules, rule)
								}
							}
						}

						return tfn, nil
					}
				}
			}
		} else {
			var answer []*operations.TfSecurityGroup
			for _, resource := range stateResources {
				if resource.Type == "azurerm_network_security_group" {
					tfn := &operations.TfSecurityGroup{}
					name := resource.AttributeValues["name"].(string)
					{
						tfn.Location = resource.AttributeValues["location"].(string)
						tfn.Identity = resource.AttributeValues["id"].(string)
						tfn.Name = name

						var ok bool
						tfn.Tags, ok = resource.AttributeValues["tags"].(map[string]string)
						if !ok {
							phase, ok := resource.AttributeValues["tags"].(map[string]any)
							if ok {
								if tfn.Tags == nil {
									tfn.Tags = make(map[string]string)
								}
								for k, v := range phase {
									tfn.Tags[k] = v.(string)
								}
							}
						}

						maybe, ok := resource.AttributeValues["security_rule"].([]any)
						if ok {
							for _, v := range maybe {
								rule, ok := v.(map[string]any)
								if ok {
									tfn.Rules = append(tfn.Rules, rule)
								}
							}
						}

						answer = append(answer, tfn)
					}
				}
			}

			return answer, nil
		}
		return nil, fail.NotFoundError("security group %s not found", hint)
	case abstract.SubnetResource:
		tfn, ok := input.(*operations.TfSubnet)
		if !ok || tfn == nil {
			if hint != "" {
				return nil, fail.NewError("failed to cast input to *operations.TfSubnet")
			}
		}

		var stateResources []*tfjson.StateResource

		stateResources = append(stateResources, tfstate.Values.RootModule.Resources...)
		for _, module := range tfstate.Values.RootModule.ChildModules {
			stateResources = append(stateResources, module.Resources...)
		}

		if hint == "" {
			var answer []*operations.TfSubnet
			for _, resource := range stateResources {
				if resource.Type == "azurerm_subnet" {
					tfn := &operations.TfSubnet{}
					// recover the subnet information
					name := resource.AttributeValues["name"].(string)
					netName := resource.AttributeValues["virtual_network_name"].(string)
					cidr := resource.AttributeValues["address_prefix"].(string)
					identity := resource.AttributeValues["id"].(string)

					maybeTags, ok := resource.AttributeValues["tags"].(map[string]any)
					if ok {
						if tfn.Tags == nil {
							tfn.Tags = make(map[string]string)
						}
						for k, v := range maybeTags {
							tfn.Tags[k] = v.(string)
						}
					}

					// and now we populate the subnet
					tfn.Name = name
					tfn.Identity = identity
					tfn.NetworkName = netName
					tfn.CIDR = cidr
					answer = append(answer, tfn)
				}
			}

			for _, atfn := range answer {
				for _, resource := range stateResources {
					if resource.Type == "azurerm_virtual_network" {
						// recover the subnet information
						name := resource.AttributeValues["name"].(string)
						if name != atfn.NetworkName {
							continue
						}

						vnetid := resource.AttributeValues["id"].(string)
						atfn.NetworkID = vnetid
					}
				}
			}

			for _, atfn := range answer {
				// now look for the network and the gateways
				for _, resource := range stateResources {
					if resource.Type == "azurerm_linux_virtual_machine" {
						// recover the subnet information
						name := resource.AttributeValues["name"].(string)
						if !(name == fmt.Sprintf("gw-%s", atfn.NetworkName) || name == fmt.Sprintf("gw2-%s", atfn.NetworkName)) {
							continue
						}

						atfn.GatewayIDS = append(atfn.GatewayIDS, resource.AttributeValues["id"].(string))
					}
				}
			}

			return answer, nil
		}

		found := false
		for _, resource := range stateResources {
			if found {
				break
			}
			if resource.Type == "azurerm_subnet" {
				// recover the subnet information
				name := resource.AttributeValues["name"].(string)
				if !(name == hint || name == fmt.Sprintf("subnet-%s", hint)) {
					continue
				}

				netName := resource.AttributeValues["virtual_network_name"].(string)
				cidr := resource.AttributeValues["address_prefix"].(string)
				identity := resource.AttributeValues["id"].(string)

				maybeTags, ok := resource.AttributeValues["tags"].(map[string]any)
				if ok {
					if tfn.Tags == nil {
						tfn.Tags = make(map[string]string)
					}
					for k, v := range maybeTags {
						tfn.Tags[k] = v.(string)
					}
				}

				found = true
				// and now we populate the subnet
				tfn.Name = name
				tfn.Identity = identity
				tfn.NetworkName = netName
				tfn.CIDR = cidr
			}
		}

		if !found {
			return nil, fail.NotFoundError("subnetwork not found")
		}

		for _, resource := range stateResources {
			if resource.Type == "azurerm_virtual_network" {
				// recover the subnet information
				name := resource.AttributeValues["name"].(string)
				if name != tfn.NetworkName {
					continue
				}

				vnetid := resource.AttributeValues["id"].(string)
				tfn.NetworkID = vnetid
			}
		}

		// now look for the network and the gateways
		for _, resource := range stateResources {
			if resource.Type == "azurerm_linux_virtual_machine" {
				// recover the subnet information
				name := resource.AttributeValues["name"].(string)
				if !(name == fmt.Sprintf("gw-%s", tfn.NetworkName) || name == fmt.Sprintf("gw2-%s", tfn.NetworkName)) {
					continue
				}

				tfn.GatewayIDS = append(tfn.GatewayIDS, resource.AttributeValues["id"].(string))
			}
		}

		return tfn, nil
	case abstract.NetworkResource:
		tfn, ok := input.(*operations.TfNetwork)
		if !ok || tfn == nil {
			if hint != "" {
				return nil, fail.NewError("failed to cast input to *operations.TfNetwork")
			}
		}

		var stateResources []*tfjson.StateResource

		stateResources = append(stateResources, tfstate.Values.RootModule.Resources...)
		for _, module := range tfstate.Values.RootModule.ChildModules {
			stateResources = append(stateResources, module.Resources...)
		}

		if hint != "" {
			for _, resource := range stateResources {
				if resource.Type == "azurerm_virtual_network" {
					// recover the subnet information
					name := resource.AttributeValues["name"].(string)
					var cidr string
					maycidr, ok := resource.AttributeValues["address_space"].([]any)
					if ok {
						if len(maycidr) > 0 {
							cidr = maycidr[0].(string)
						}
					}
					identity := resource.AttributeValues["id"].(string)

					if !(name == hint || identity == hint || name == fmt.Sprintf("network-%s", hint)) {
						continue
					}

					// and now we populate the subnet
					tfn.Name = name
					tfn.Identity = identity
					tfn.CIDR = cidr

					maybeTags, ok := resource.AttributeValues["tags"].(map[string]any)
					if ok {
						if tfn.Tags == nil {
							tfn.Tags = make(map[string]string)
						}
						for k, v := range maybeTags {
							tfn.Tags[k] = v.(string)
						}
					}

					maybeSubnetStruct, ok := resource.AttributeValues["subnet"].([]any)
					if ok {
						if len(maybeSubnetStruct) > 0 {
							subnetStruct := maybeSubnetStruct[0].(map[string]any)
							tfn.SubnetCidr = subnetStruct["address_prefix"].(string)
							tfn.SubnetId = subnetStruct["id"].(string)
							tfn.SubnetName = subnetStruct["name"].(string)
						}
					}

					return tfn, nil
				}
			}
		} else {
			var answer []*operations.TfNetwork
			for _, resource := range stateResources {
				if resource.Type == "azurerm_virtual_network" {
					tfn := &operations.TfNetwork{}

					// recover the subnet information
					name := resource.AttributeValues["name"].(string)
					var cidr string
					maycidr, ok := resource.AttributeValues["address_space"].([]any)
					if ok {
						if len(maycidr) > 0 {
							cidr = maycidr[0].(string)
						}
					}
					identity := resource.AttributeValues["id"].(string)

					// and now we populate the subnet
					tfn.Name = name
					tfn.Identity = identity
					tfn.CIDR = cidr

					maybeTags, ok := resource.AttributeValues["tags"].(map[string]any)
					if ok {
						if tfn.Tags == nil {
							tfn.Tags = make(map[string]string)
						}
						for k, v := range maybeTags {
							tfn.Tags[k] = v.(string)
						}
					}

					maybeSubnetStruct, ok := resource.AttributeValues["subnet"].([]any)
					if ok {
						if len(maybeSubnetStruct) > 0 {
							subnetStruct := maybeSubnetStruct[0].(map[string]any)
							tfn.SubnetCidr = subnetStruct["address_prefix"].(string)
							tfn.SubnetId = subnetStruct["id"].(string)
							tfn.SubnetName = subnetStruct["name"].(string)
						}
					}

					answer = append(answer, tfn)
				}
			}
			return answer, nil
		}

		return nil, fail.NotFoundError("network %s not found", hint)
	case abstract.HostResource:
		t, ok := input.(*operations.TfHost)
		if !ok || t == nil {
			if hint != "" {
				return nil, fail.NewError("failed to cast input to *operations.TfHost")
			}
		}

		var stateResources []*tfjson.StateResource

		stateResources = append(stateResources, tfstate.Values.RootModule.Resources...)
		for _, module := range tfstate.Values.RootModule.ChildModules {
			stateResources = append(stateResources, module.Resources...)
		}

		if hint == "" {
			answer := []*operations.TfHost{}
			for _, resource := range stateResources {
				if resource.Type == "azurerm_linux_virtual_machine" {
					t := &operations.TfHost{}
					computerName, ok := resource.AttributeValues["computer_name"].(string)
					if !ok {
						continue
					}

					{
						t.ID = resource.AttributeValues["id"].(string)
						t.Name = computerName
						t.Password = resource.AttributeValues["admin_password"].(string)
						t.Tags, ok = resource.AttributeValues["tags"].(map[string]string)
						if !ok {
							phase, ok := resource.AttributeValues["tags"].(map[string]any)
							if ok {
								t.Tags = make(map[string]string)
								for k, v := range phase {
									t.Tags[k] = v.(string)
								}
							}
						}

						t.SSHPort = 22 // FIXME: fix this later
						t.InternalTerraformID = resource.Address
						t.TemplateSize = resource.AttributeValues["size"].(string)
						t.VmIdentity = resource.AttributeValues["virtual_machine_id"].(string)

						t.PublicIP = resource.AttributeValues["public_ip_address"].(string)
						t.PrivateIP = resource.AttributeValues["private_ip_address"].(string)

						maybeIDs, ok := resource.AttributeValues["network_interface_ids"].([]any)
						if ok {
							for _, v := range maybeIDs {
								t.Nics = append(t.Nics, v.(string))
							}
						}

						for k, v := range t.Tags {
							if k == "NetworkID" {
								t.NetworkIDs = append(t.NetworkIDs, v)
							}
							if k == "SubnetID" {
								t.SubnetID = v
							}
						}

						maybe, ok := resource.AttributeValues["admin_ssh_key"].([]any)
						if ok {
							if len(maybe) > 0 {
								keyStruct := maybe[0].(map[string]interface{})
								t.PrivateKey = keyStruct["public_key"].(string)
								t.Operator = keyStruct["username"].(string)
							}
						}

						maybe, ok = resource.AttributeValues["os_disk"].([]any)
						if ok {
							if len(maybe) > 0 {
								osDiskStruct := maybe[0].(map[string]interface{})
								jn := osDiskStruct["disk_size_gb"].(json.Number)
								val, _ := jn.Int64()
								t.DiskSizeInGb = int32(val)
							}
						}

						answer = append(answer, t)
					}
				}
			}

			for _, t := range answer {
				// if we have "NetworkName", we have to use it
				var networkName string
				if val, ok := t.Tags["NetworkName"]; ok {
					networkName = val
				} else {
					// get the network name from the host name
					if strings.HasPrefix(t.Name, "gw") {
						networkName = strings.Split(t.Name, "-")[1]
					} else {
						networkName = strings.Split(t.Name, "-")[0]
					}
				}

				t.Network = networkName

				foundKey := false
				// now look for the private key
				for _, resource := range stateResources {
					if foundKey {
						break
					}
					if resource.Type == "tls_private_key" {
						if resource.Name == fmt.Sprintf("ssh-%s", t.Name) {
							t.PrivateKey = resource.AttributeValues["private_key_pem"].(string)
							break
						}

						for _, dep := range resource.DependsOn {
							if strings.Contains(dep, networkName) { // the right network
								switch resource.Name {
								case "ssh":
									if strings.HasPrefix(t.Name, "gw") {
										t.PrivateKey = resource.AttributeValues["private_key_pem"].(string)
										foundKey = true
										break
									}
								case "ssh_node":
									if strings.Contains(t.Name, "-node") {
										t.PrivateKey = resource.AttributeValues["private_key_pem"].(string)
										foundKey = true
										break
									}
								case "ssh_master":
									if strings.Contains(t.Name, "-master") {
										t.PrivateKey = resource.AttributeValues["private_key_pem"].(string)
										foundKey = true
										break
									}
								default:
								}
								if foundKey {
									break
								}
							}
						}
					}
				}
			}
			return answer, nil
		}

		found := false
		for _, resource := range stateResources {
			if found {
				break
			}
			if resource.Type == "azurerm_linux_virtual_machine" {
				computerName, ok := resource.AttributeValues["computer_name"].(string)
				if !ok {
					continue
				}

				vmID, ok := resource.AttributeValues["virtual_machine_id"].(string)
				if !ok {
					continue
				}

				if computerName == hint || vmID == hint {
					t.ID = resource.AttributeValues["id"].(string)
					t.Name = computerName
					t.Password = resource.AttributeValues["admin_password"].(string)
					t.Tags, ok = resource.AttributeValues["tags"].(map[string]string)
					if !ok {
						phase, ok := resource.AttributeValues["tags"].(map[string]any)
						if ok {
							t.Tags = make(map[string]string)
							for k, v := range phase {
								t.Tags[k] = v.(string)
							}
						}
					}

					t.SSHPort = 22 // FIXME: fix this later
					t.InternalTerraformID = resource.Address
					t.TemplateSize = resource.AttributeValues["size"].(string)
					t.VmIdentity = resource.AttributeValues["virtual_machine_id"].(string)

					t.PublicIP = resource.AttributeValues["public_ip_address"].(string)
					t.PrivateIP = resource.AttributeValues["private_ip_address"].(string)

					maybeIDs, ok := resource.AttributeValues["network_interface_ids"].([]any)
					if ok {
						for _, v := range maybeIDs {
							t.Nics = append(t.Nics, v.(string))
						}
					}

					for k, v := range t.Tags {
						if k == "NetworkID" {
							t.NetworkIDs = append(t.NetworkIDs, v)
						}
						if k == "SubnetID" {
							t.SubnetID = v
						}
					}

					maybe, ok := resource.AttributeValues["admin_ssh_key"].([]any)
					if ok {
						if len(maybe) > 0 {
							keyStruct := maybe[0].(map[string]interface{})
							t.PrivateKey = keyStruct["public_key"].(string)
							t.Operator = keyStruct["username"].(string)
						}
					}

					maybe, ok = resource.AttributeValues["os_disk"].([]any)
					if ok {
						if len(maybe) > 0 {
							osDiskStruct := maybe[0].(map[string]interface{})
							jn := osDiskStruct["disk_size_gb"].(json.Number)
							val, _ := jn.Int64()
							t.DiskSizeInGb = int32(val)
						}
					}

					found = true
				}
			}
		}

		if !found {
			return nil, fail.NotFoundError("host not found: %s", hint)
		}

		// if we have "NetworkName", we have to use it
		var networkName string
		if val, ok := t.Tags["NetworkName"]; ok {
			networkName = val
		} else {
			// get the network name from the host name
			if strings.HasPrefix(t.Name, "gw") {
				networkName = strings.Split(t.Name, "-")[1]
			} else {
				networkName = strings.Split(t.Name, "-")[0]
			}
		}

		t.Network = networkName

		foundKey := false
		// now look for the private key
		for _, resource := range stateResources {
			if foundKey {
				break
			}
			if resource.Type == "tls_private_key" {
				if resource.Name == fmt.Sprintf("ssh-%s", t.Name) {
					t.PrivateKey = resource.AttributeValues["private_key_pem"].(string)
					break
				}

				for _, dep := range resource.DependsOn {
					if strings.Contains(dep, networkName) { // the right network
						switch resource.Name {
						case "ssh":
							if strings.HasPrefix(t.Name, "gw") {
								t.PrivateKey = resource.AttributeValues["private_key_pem"].(string)
								foundKey = true
								break
							}
						case "ssh_node":
							if strings.Contains(t.Name, "-node") {
								t.PrivateKey = resource.AttributeValues["private_key_pem"].(string)
								foundKey = true
								break
							}
						case "ssh_master":
							if strings.Contains(t.Name, "-master") {
								t.PrivateKey = resource.AttributeValues["private_key_pem"].(string)
								foundKey = true
								break
							}
						default:
						}
						if foundKey {
							break
						}
					}
				}
			}
		}

		// FIXME: and now, look for the private key of the gateway and the public ip of the gateway

		return t, nil
	default:
		return nil, fail.NotImplementedError("resource of type %d not implemented", kind)
	}
}

func (s stack) GetTerraformState(ctx context.Context) (*tfjson.State, fail.Error) {
	tf, err := tfexec.NewTerraform(s.workPath, s.execPath)
	if err != nil {
		return nil, fail.ConvertError(fmt.Errorf("error running terraform NewTerraform: %w", err))
	}

	tfstate, err := tf.Show(ctx)
	if err != nil {
		return nil, fail.ConvertError(fmt.Errorf("error running terraform Show: %w", err))
	}

	valid := false
	if tfstate != nil {
		if tfstate.Values != nil {
			if tfstate.Values.RootModule != nil {
				if res := tfstate.Values.RootModule.Resources; res != nil {
					if len(res) > 0 {
						valid = true
					}
				}
				if res := tfstate.Values.RootModule.ChildModules; res != nil {
					if len(res) > 0 {
						for _, child := range res {
							if len(child.Resources) > 0 {
								valid = true
								break
							}
						}
					}
				}
			}
		}
	}
	if !valid {
		return nil, fail.NotFoundError("failed to load terraform state, it's empty")
	}

	if tfstate.Values != nil {
		return tfstate, nil
	}

	return nil, fail.ConvertError(fmt.Errorf("no outputs found in terraform state"))
}

func (s stack) Render(ctx context.Context, kind abstract.Enum, source string, options map[string]any) ([]abstract.RenderedContent, fail.Error) {
	switch kind {
	case abstract.ObjectStorageBucketResource:
		rgString, err := templates.ReadFile(fmt.Sprintf("templates/%s/buckets-rg.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading disk template")
		}
		if len(rgString) == 0 {
			return nil, fail.NewError("template not found")
		}

		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/bucket.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading bucket template")
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: "buckets-rg.tf", Content: string(rgString), Complete: false}, {Name: "bucket.tf", Content: string(tmplString), Complete: false}}, nil
	case abstract.VolumeAttachmentResource:
		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/attachments.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading disk attachment script")
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: "attachment-machine-disk.tf", Content: string(tmplString), Complete: false}}, nil
	case abstract.SecurityGroupResource:
		rgString, err := templates.ReadFile(fmt.Sprintf("templates/%s/sg-rg.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading security group template")
		}
		if len(rgString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: "securitygroup.tf", Content: string(rgString), Complete: false}}, nil
	case abstract.VolumeResource:
		rgString, err := templates.ReadFile(fmt.Sprintf("templates/%s/disks-rg.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading disk template")
		}
		if len(rgString) == 0 {
			return nil, fail.NewError("template not found")
		}

		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/disks-template.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading firewall script")
		}
		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: "diskrg.tf", Content: string(rgString), Complete: false}, {Name: "disk.tf", Content: string(tmplString), Complete: false}}, nil
	case abstract.ProviderResource:
		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/providers.tfvars", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading provider template")
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		type Creds struct {
			AzureTenantID       string
			AzureSubscriptionID string
		}

		buf := bytes.Buffer{}
		pt, err := template.New("init").Parse(string(tmplString))
		if err != nil {
			return nil, fail.Wrap(err, "error parsing provider template")
		}
		err = pt.Execute(&buf, Creds{
			AzureTenantID:       options["AzureTenantID"].(string),
			AzureSubscriptionID: options["AzureSubscriptionID"].(string),
		})
		if err != nil {
			return nil, fail.Wrap(err, "error executing provider template")
		}

		return []abstract.RenderedContent{{Name: "providers.tf", Content: buf.String()}}, nil
	case abstract.ClusterResource:
		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/main.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading main cluster template")
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		tagString, err := templates.ReadFile(fmt.Sprintf("templates/%s/main-tags.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading machine tag template")
		}

		if len(tagString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: "main.tf", Content: string(tmplString)}, {Name: "machine-tags-gw.tf", Content: string(tagString), Complete: false}}, nil
	case abstract.HostResource:
		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/machine-template.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading machine template")
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		tagString, err := templates.ReadFile(fmt.Sprintf("templates/%s/machine-tags.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading machine tag template")
		}

		if len(tagString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: fmt.Sprintf("machine.tf"), Content: string(tmplString), Complete: false}, {Name: "machine-tags.tf", Content: string(tagString), Complete: false}}, nil
	case abstract.FirewallResource:
		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/firewall.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading firewall script")
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: "firewall.tf", Content: string(tmplString), Complete: false}}, nil
	case abstract.FirewallRuleResource:
		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/firewallrule-template.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading firewall rule script")
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: "firewall-rule.tf", Content: string(tmplString), Complete: false}}, nil
	case abstract.VariableResource:
		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/variables.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading variables.tf")
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: "variables.tf", Content: string(tmplString)}}, nil
	case abstract.InitScript:
		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/init.sh", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading script template for phase 'init'")
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: "init.sh", Content: string(tmplString)}}, nil
	case abstract.GwInitScript:
		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/gw-init.sh", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading script template for phase 'init'")
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: "gw-init.sh", Content: string(tmplString)}}, nil
	case abstract.OutputResource:
		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/outputs.tf", source))
		if err != nil {
			return nil, fail.Wrap(err, "error loading script template for outputs")
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: "outputs.tf", Content: string(tmplString)}}, nil
	case abstract.CustomResource:
		tmplString, err := templates.ReadFile(fmt.Sprintf("templates/%s/%s", source, options["custom"]))
		if err != nil {
			return nil, fail.Wrap(err, "error reading file '%s'", options["custom"])
		}

		if len(tmplString) == 0 {
			return nil, fail.NewError("template not found")
		}

		return []abstract.RenderedContent{{Name: options["custom"].(string), Content: string(tmplString)}}, nil
	default:
		return nil, fail.NotImplementedError("rendering of kind '%s' is not implemented", kind.String())
	}
}
