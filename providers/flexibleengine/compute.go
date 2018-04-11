package flexibleengine

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/IPVersion"
	"github.com/SafeScale/providers/api/VMState"
	"github.com/SafeScale/providers/api/VolumeSpeed"
	uuid "github.com/satori/go.uuid"

	ex_bfv "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/bootfromvolume"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
)

//VMRequest - FlexibleEngine needs some supplementary fields when requesting a VM
type VMRequest struct {
	*api.VMRequest

	// Enable or disable the router mode of the VM in Flexible Engine
	RouterMode bool
}

//VM - FlexibleEngine VM represents a virtual machine properties
type VM struct {
	*api.VM
	RouterMode bool `json:"router_mode,omitempty"`
}

//createVM -
func (client *Client) createVM(request VMRequest, isGateway bool) (*VM, error) {
	//Eventual network gateway
	var gw *api.VM
	/*	//If the VM is not public it has to be created on a network owning a Gateway
		if !request.PublicIP {
			gwServer, err := client.readGateway(request.NetworkIDs[0])
			if err != nil {
				return nil, fmt.Errorf("No public VM cannot be created on a network without gateway")
			}
			gw, err = client.readVMDefinition(gwServer.ID)
			if err != nil {
				return nil, fmt.Errorf("Bad state, Gateway for network %s is not accessible", request.NetworkIDs[0])
			}
		}
	*/

	var nets []servers.Network
	//If floating IPs are not used and VM is public
	//then add provider network to VM networks
	//if !client.Cfg.UseFloatingIP && request.PublicIP {
	//	nets = append(nets, servers.Network{
	//		UUID: client.ProviderNetworkID,
	//	})
	//}
	//Add private networks
	for _, n := range request.NetworkIDs {
		nets = append(nets, servers.Network{
			UUID: n,
		})
	}

	//Prepare key pair
	kp := request.KeyPair
	var err error
	//If no key pair is supplied create one
	if kp == nil {
		id, _ := uuid.NewV4()
		name := fmt.Sprintf("%s_%s", request.Name, id)
		kp, err = client.CreateKeyPair(name)
		if err != nil {
			return nil, fmt.Errorf("Error creating VM: %s", errorString(err))
		}
		defer client.DeleteKeyPair(kp.ID)
	}

	if err != nil {
		return nil, err
	}

	userData, err := client.PrepareUserData(*request.VMRequest, isGateway, kp, gw)
	//fmt.Println(string(userData))

	// Configure block device for system disk
	volreq := api.VolumeRequest{
		Size:  100,
		Name:  request.Name,
		Speed: VolumeSpeed.SSD,
	}
	bootvol, err := client.ExCreateVolume(volreq, request.ImageID)
	if err != nil {
		return nil, fmt.Errorf("Error creating Boot Volume: %s", errorString(err))
	}
	bootDiskOpts := ex_bfv.BlockDevice{
		SourceType: ex_bfv.SourceVolume,
		//DestinationType:     "volume",
		BootIndex:           0,
		DeleteOnTermination: true,
		UUID:                bootvol.ID,
	}
	// Create VM options
	srvOpts := servers.CreateOpts{
		Name:           request.Name,
		SecurityGroups: []string{client.SecurityGroup.Name},
		Networks:       nets,
		FlavorRef:      request.TemplateID,
		ImageRef:       request.ImageID,
		UserData:       userData,
	}
	// Create VM "Extension bootfromvolume" options
	exSrvOpts := ex_bfv.CreateOptsExt{
		CreateOptsBuilder: srvOpts,
		BlockDevice:       []ex_bfv.BlockDevice{bootDiskOpts},
	}
	// Create VM
	server, err := ex_bfv.Create(client.Compute, keypairs.CreateOptsExt{
		CreateOptsBuilder: exSrvOpts,
		KeyName:           kp.ID,
	}).Extract()
	if err != nil {
		if server != nil {
			servers.Delete(client.Compute, server.ID)
			client.DeleteVolume(bootvol.ID)
		}
		return nil, fmt.Errorf("Error creating VM: %s", errorString(err))
	}
	// Wait that VM is started
	service := providers.Service{
		ClientAPI: client,
	}
	vm, err := service.WaitVMState(server.ID, VMState.STARTED, 120*time.Second)
	if err != nil {
		return nil, fmt.Errorf("Timeout creating VM: %s", errorString(err))
	}

	exvm := VM{
		VM:         vm,
		RouterMode: request.RouterMode,
	}

	//Add gateway ID to VM definition (VPL: not sure if it's needed with FlexibleEngine...)
	/*	var gwID string
		if gw != nil {
			gwID = gw.ID
		}
		vm.GatewayID = gwID*/
	exvm.VM.PrivateKey = kp.PrivateKey
	//if Floating IP are not used or no public address is requested
	if /*!client.Cfg.UseFloatingIP || */ !request.PublicIP {
		err = client.saveVMDefinition(exvm)
		if err != nil {
			client.DeleteVM(exvm.VM.ID)
			client.DeleteVolume(bootvol.ID)
			return nil, fmt.Errorf("Error creating VM: %s", errorString(err))
		}
		return &exvm, nil
	}

	/* VPL: Probablement à revoir... */
	//Create the floating IP
	ip, err := floatingips.Create(client.Compute, floatingips.CreateOpts{
		//Pool: client.Opts.FloatingIPPool,
	}).Extract()
	if err != nil {
		servers.Delete(client.Compute, exvm.VM.ID)
		return nil, fmt.Errorf("Error creating VM: %s", errorString(err))
	}

	//Associate floating IP to VM
	err = floatingips.AssociateInstance(client.Compute, exvm.VM.ID, floatingips.AssociateOpts{
		FloatingIP: ip.IP,
	}).ExtractErr()
	if err != nil {
		floatingips.Delete(client.Compute, ip.ID)
		servers.Delete(client.Compute, exvm.VM.ID)
		return nil, fmt.Errorf("Error creating VM: %s", errorString(err))
	}

	// Enable router mode if needed
	if request.RouterMode {
		client.enableRouterMode(&exvm)
	}

	if IPVersion.IPv4.Is(ip.IP) {
		exvm.VM.AccessIPv4 = ip.IP
	} else if IPVersion.IPv6.Is(ip.IP) {
		exvm.VM.AccessIPv6 = ip.IP
	}
	err = client.saveVMDefinition(exvm)
	if err != nil {
		client.DeleteVM(exvm.VM.ID)
		return nil, fmt.Errorf("Error creating VM: %s", errorString(err))
	}

	return &exvm, nil
}

//DeleteVM deletes the VM identified by id
func (client *Client) DeleteVM(id string) error {
	// Retrieve the list of attached volumes before deleting the VM
	volumeAttachments, err := client.ListVolumeAttachments(id)
	if err != nil {
		return err
	}
	// Deletes the VM
	err = client.Client.DeleteVM(id)
	// In FlexibleEngine, volume are not always automatically remove, so take care of it
	for _, va := range volumeAttachments {
		volume, err := client.GetVolume(va.VolumeID)
		if err != nil {
			continue
		}
		err = client.DeleteVolume(volume.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

/*
 * Gathers system disk size from the volume, FlexibleEngine template doesn't
 * contain this information
 * :param node: Node object
 * :return: int: size in GB of the system disk
 *          error: nil on success, error on failure
 */
func (client *Client) getSystemDiskSize(vm *VM) (int, error) {
	volumeAttachments, err := client.ListVolumeAttachments(vm.VM.ID)
	if err != nil {
		return 0, err
	}
	volumeAttachment := volumeAttachments[0]
	volume, err := client.GetVolume(volumeAttachment.VolumeID)
	if err != nil {
		return 0, err
	}
	return volume.Size, nil
}

/**
 * Disables the source/destination check on NIC corresponding to the private_ip of the node.
 * This allows the NIC to serve as router/gateway.
 * :param node_id:
 * :param private_ip:
 * :return:
 */
func (client *Client) enableRouterMode(vm *VM) error {
	/* VPL: Python code to port in GO
	port_id, err := client.getPortIDFromIP(vm.ID, vm.PrivateIPsV4)
		if err != nil {
			return err
		}
		data := {
			"port": {
				"allowed_address_pairs": [
					{
						"ip_address": "1.1.1.1/0"
					}
				]
			}
		}
		cnx = self._open_connection_on_network_endpoint()
		resp = cnx.request(method="PUT", action="/v2.0/ports/%s" % port_id, data=data)
		if resp and resp.success():
			logger.info("Router mode enabled on node %s", node_id)
			return
		logger.error("Failed to enable router mode on node %s", node_id)
	*/
	return nil
}

func (client *Client) saveVMDefinition(vm VM) error {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(vm)
	if err != nil {
		return err
	}
	return client.PutObject("__vms__", api.Object{
		Name:    vm.ID,
		Content: bytes.NewReader(buffer.Bytes()),
	})
}

func (client *Client) removeVMDefinition(vmID string) error {
	return client.DeleteObject("__vms__", vmID)
}

func (client *Client) readVMDefinition(vmID string) (*VM, error) {
	o, err := client.GetObject("__vms__", vmID, nil)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.ReadFrom(o.Content)
	enc := gob.NewDecoder(&buffer)
	var vm VM
	err = enc.Decode(&vm)
	if err != nil {
		return nil, err
	}
	return &vm, nil
}
