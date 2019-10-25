package aws

import (
	"encoding/json"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostProperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"strings"
	"time"
)

func (s *Stack) ListAvailabilityZones() (map[string]bool, error) {
	zones := make(map[string]bool)

	ro, err := s.EC2Service.DescribeAvailabilityZones(&ec2.DescribeAvailabilityZonesInput{})
	if err != nil {
		return zones, err
	}
	if ro != nil {
		for _, zone := range ro.AvailabilityZones {
			zoneName := aws.StringValue(zone.ZoneName)
			if zoneName != "" {
				zones[zoneName] = aws.StringValue(zone.State) == "available"
			}
		}
	}

	return zones, nil
}

func (s *Stack) ListRegions() ([]string, error) {
	var regions []string

	ro, err := s.EC2Service.DescribeRegions(&ec2.DescribeRegionsInput{})
	if err != nil {
		return regions, err
	}
	if ro != nil {
		for _, region := range ro.Regions {
			regions = append(regions, region.String())
		}
	}

	return regions, nil
}

func (s *Stack) GetImage(id string) (*resources.Image, error) {
	imagesList, err := s.ListImages()
	if err != nil {
		return nil, err
	}
	for _, res := range imagesList {
		if res.ID == id {
			return &res, nil
		}
	}

	return nil, resources.ResourceNotFoundError("Image", id)
}

func (s *Stack) GetTemplate(id string) (*resources.HostTemplate, error) {
	template := resources.HostTemplate{}

	prods, err := s.PricingService.GetProducts(&pricing.GetProductsInput{
		Filters: []*pricing.Filter{
			{
				Field: aws.String("ServiceCode"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("AmazonEC2"),
			},
			{
				Field: aws.String("operatingSystem"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("Linux"),
			},
			{
				Field: aws.String("instanceType"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String(id),
			},
		},
		MaxResults:  aws.Int64(100),
		ServiceCode: aws.String("AmazonEC2"),
	})
	if err != nil {
		return &template, err
	}

	for _, price := range prods.PriceList {
		jsonPrice, err := json.Marshal(price)
		if err != nil {
			continue
		}
		price := Price{}
		err = json.Unmarshal(jsonPrice, &price)
		if err != nil {
			continue
		}

		tpl := resources.HostTemplate{
			ID:        price.Product.Attributes.InstanceType,
			Name:      price.Product.Attributes.InstanceType,
			Cores:     ParseNumber(price.Product.Attributes.Vcpu, 1),
			GPUNumber: ParseNumber(price.Product.Attributes.Gpu, 0),
			DiskSize:  int(ParseStorage(price.Product.Attributes.Storage)),
			RAMSize:   float32(ParseMemory(price.Product.Attributes.Memory)),
		}

		template = tpl
		break
	}

	return &template, nil
}

func createFilters() []*ec2.Filter {
	filters := []*ec2.Filter{
		&ec2.Filter{
			Name:   aws.String("state"),
			Values: []*string{aws.String("available")},
		},
		&ec2.Filter{
			Name:   aws.String("architecture"),
			Values: []*string{aws.String("x86_64")},
		},
		&ec2.Filter{
			Name:   aws.String("virtualization-type"),
			Values: []*string{aws.String("hvm")},
		},
		&ec2.Filter{
			Name:   aws.String("root-device-type"),
			Values: []*string{aws.String("ebs")},
		},
	}
	// Ubuntu 099720109477
	// Fedora 013116697141
	// Debian 379101102735
	// CentOS 057448758665
	// CoreOS 595879546273
	// Gentoo 341857463381
	owners := []*string{
		aws.String("099720109477"),
		aws.String("013116697141"),
		aws.String("379101102735"),
		aws.String("057448758665"),
		aws.String("595879546273"),
		aws.String("902460189751"),
	}
	filters = append(filters, &ec2.Filter{
		Name:   aws.String("owner-id"),
		Values: owners,
	})
	return filters
}

// FIXME Orphan method
func (s *Stack) ListImages() ([]resources.Image, error) {
	var images []resources.Image

	filters := []*ec2.Filter{
		&ec2.Filter{
			Name:   aws.String("architecture"),
			Values: []*string{aws.String("x86_64")},
		},
		&ec2.Filter{
			Name:   aws.String("state"),
			Values: []*string{aws.String("available")},
		},
	}

	// Added filtering by owner-id
	filters = append(filters, createFilters()...)

	iout, err := s.EC2Service.DescribeImages(&ec2.DescribeImagesInput{
		Filters: filters,
	})
	if err != nil {
		return images, err
	}
	if iout != nil {
		for _, image := range iout.Images {
			if image != nil {
				images = append(images, resources.Image{
					ID:   aws.StringValue(image.ImageId),
					Name: aws.StringValue(image.Name),
				})
			}
		}
	}

	return images, nil
}

// FIXME Orphan method
func (s *Stack) ListTemplates() ([]resources.HostTemplate, error) {
	var templates []resources.HostTemplate

	prods, err := s.PricingService.GetProducts(&pricing.GetProductsInput{
		Filters: []*pricing.Filter{
			{
				Field: aws.String("ServiceCode"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("AmazonEC2"),
			},
			{
				Field: aws.String("operatingSystem"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("Linux"),
			},
		},
		MaxResults:  aws.Int64(100),
		ServiceCode: aws.String("AmazonEC2"),
	})
	if err != nil {
		return templates, err
	}

	hostTemplates := make(map[string]resources.HostTemplate)

	for _, price := range prods.PriceList {
		jsonPrice, err := json.Marshal(price)
		if err != nil {
			continue
		}
		price := Price{}
		err = json.Unmarshal(jsonPrice, &price)
		if err != nil {
			continue
		}

		tpl := resources.HostTemplate{
			ID:        price.Product.Attributes.InstanceType,
			Name:      price.Product.Attributes.InstanceType,
			Cores:     ParseNumber(price.Product.Attributes.Vcpu, 1),
			GPUNumber: ParseNumber(price.Product.Attributes.Gpu, 0),
			DiskSize:  int(ParseStorage(price.Product.Attributes.Storage)),
			RAMSize:   float32(ParseMemory(price.Product.Attributes.Memory)),
		}

		hostTemplates[price.Product.Attributes.InstanceType] = tpl
	}

	for _, v := range hostTemplates {
		templates = append(templates, v)
	}

	return templates, nil
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *resources.Host; any other type will panic
func (s *Stack) WaitHostReady(hostParam interface{}, timeout time.Duration) (*resources.Host, error) {
	if s == nil {
		panic("Calling s.WaitHostReady with s==nil!")
	}

	var (
		host *resources.Host
	)
	switch hostParam.(type) {
	case string:
		host = resources.NewHost()
		host.ID = hostParam.(string)
	case *resources.Host:
		host = hostParam.(*resources.Host)
	default:
		panic("hostParam must be a string or a *resources.Host!")
	}
	logrus.Debugf(">>> stacks.gcp::WaitHostReady(%s)", host.ID)
	defer logrus.Debugf("<<< stacks.gcp::WaitHostReady(%s)", host.ID)

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(host)
			if err != nil {
				return err
			}

			host = hostTmp
			if host.LastState != HostState.STARTED {
				return fmt.Errorf("not in ready state (current state: %s)", host.LastState.String())
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		timeout,
	)
	if retryErr != nil {
		if _, ok := retryErr.(retry.ErrTimeout); ok {
			return host, fmt.Errorf("timeout waiting to get host '%s' information after %v", host.Name, timeout)
		}
		return host, retryErr
	}
	return host, nil
}

func (s *Stack) CreateHost(request resources.HostRequest) (host *resources.Host, userData *userdata.Content, err error) {
	userData = userdata.NewContent()

	resourceName := request.ResourceName
	networks := request.Networks
	hostMustHavePublicIP := request.PublicIP

	if networks == nil || len(networks) == 0 {
		return nil, userData, fmt.Errorf("the host %s must be on at least one network (even if public)", resourceName)
	}

	// If no key pair is supplied create one
	if request.KeyPair == nil {
		id, err := uuid.NewV4()
		if err != nil {
			msg := fmt.Sprintf("failed to create host UUID: %+v", err)
			logrus.Debugf(utils.Capitalize(msg))
			return nil, userData, fmt.Errorf(msg)
		}

		name := fmt.Sprintf("%s_%s", request.ResourceName, id)
		request.KeyPair, err = s.CreateKeyPair(name)
		if err != nil {
			msg := fmt.Sprintf("failed to create host key pair: %+v", err)
			logrus.Debugf(utils.Capitalize(msg))
			return nil, userData, fmt.Errorf(msg)
		}
	}

	// If no password is provided, create one
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nil, userData, fmt.Errorf("failed to generate password: %s", err.Error())
		}
		request.Password = password
	}

	// The Default Network is the first of the provided list, by convention
	defaultNetwork := request.Networks[0]
	defaultNetworkID := defaultNetwork.ID
	defaultGateway := request.DefaultGateway
	isGateway := defaultGateway == nil && defaultNetwork.Name != resources.SingleHostNetworkName
	defaultGatewayID := ""
	defaultGatewayPrivateIP := ""
	if defaultGateway != nil {
		err := defaultGateway.Properties.LockForRead(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
			hostNetworkV1 := v.(*propertiesv1.HostNetwork)
			defaultGatewayPrivateIP = hostNetworkV1.IPv4Addresses[defaultNetworkID]
			defaultGatewayID = defaultGateway.ID
			return nil
		})
		if err != nil {
			return nil, userData, errors.Wrap(err, "")
		}
	}

	if defaultGateway == nil && !hostMustHavePublicIP {
		return nil, userData, fmt.Errorf("the host %s must have a gateway or be public", resourceName)
	}

	var nets []servers.Network

	// FIXME add provider network to host networks ?

	// Add private networks
	for _, n := range request.Networks {
		nets = append(nets, servers.Network{
			UUID: n.ID,
		})
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	err = userData.Prepare(*s.Config, request, defaultNetwork.CIDR, "")
	if err != nil {
		msg := fmt.Sprintf("failed to prepare user data content: %+v", err)
		logrus.Debugf(utils.Capitalize(msg))
		return nil, userData, fmt.Errorf(msg)
	}

	// Determine system disk size based on vcpus count
	template, err := s.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, userData, fmt.Errorf("failed to get image: %s", err)
	}

	rim, err := s.GetImage(request.ImageID)
	if err != nil {
		return nil, nil, err
	}

	logrus.Debugf("Selected template: '%s', '%s'", template.ID, template.Name)

	// Select usable availability zone, the first one in the list
	if s.AwsConfig.Zone == "" {
		azList, err := s.ListAvailabilityZones()
		if err != nil {
			return nil, userData, err
		}
		var az string
		for az = range azList {
			break
		}
		s.AwsConfig.Zone = az
		logrus.Debugf("Selected Availability Zone: '%s'", az)
	}

	// Sets provider parameters to create host
	userDataPhase1, err := userData.Generate("phase1")
	if err != nil {
		return nil, userData, err
	}

	// --- Initializes resources.Host ---

	host = resources.NewHost()
	host.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to host definition
	host.Password = request.Password

	err = host.Properties.LockForWrite(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
		hostNetworkV1 := v.(*propertiesv1.HostNetwork)
		hostNetworkV1.DefaultNetworkID = defaultNetworkID
		hostNetworkV1.DefaultGatewayID = defaultGatewayID
		hostNetworkV1.DefaultGatewayPrivateIP = defaultGatewayPrivateIP
		hostNetworkV1.IsGateway = isGateway
		return nil
	})
	if err != nil {
		return nil, userData, err
	}

	// Adds Host property SizingV1
	err = host.Properties.LockForWrite(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
		hostSizingV1 := v.(*propertiesv1.HostSizing)
		// Note: from there, no idea what was the RequestedSize; caller will have to complement this information
		hostSizingV1.Template = request.TemplateID
		hostSizingV1.AllocatedSize = properties.ModelHostTemplateToPropertyHostSize(template)
		return nil
	})
	if err != nil {
		return nil, userData, err
	}

	// --- query provider for host creation ---

	logrus.Debugf("requesting host resource creation...")
	var desistError error

	// Retry creation until success, for 10 minutes
	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {

			server, err := buildAwsMachine(s.EC2Service, request.ResourceName, rim.ID, s.AwsConfig.Zone, defaultNetwork.Name, string(userDataPhase1), isGateway, template)
			if err != nil {
				if server != nil {
					killErr := s.DeleteHost(server.ID)
					if killErr != nil {
						return errors.Wrap(err, killErr.Error())
					}
				}

				if isAWSErr(err) {
					desistError = err
					return nil
				}

				logrus.Warnf("error creating host: %+v", err)
				return err
			}

			if server == nil {
				return fmt.Errorf("failed to create server")
			}

			host.ID = server.ID
			host.Name = server.Name

			// Wait that Host is ready, not just that the build is started
			_, err = s.WaitHostReady(host, temporal.GetLongOperationTimeout())
			if err != nil {
				killErr := s.DeleteHost(host.ID)
				if killErr != nil {
					return errors.Wrap(err, killErr.Error())
				}
				return err
			}
			return nil
		},
		temporal.GetLongOperationTimeout(),
	)
	if err != nil {
		return nil, userData, errors.Wrap(err, fmt.Sprintf("Error creating host: timeout"))
	}
	if desistError != nil {
		return nil, userData, scerr.ForbiddenError(fmt.Sprintf("Error creating host: %s", desistError.Error()))
	}

	logrus.Debugf("host resource created.")

	// Starting from here, delete host if exiting with error
	defer func() {
		if err != nil { // FIXME Handle error groups
			logrus.Infof("Cleanup, deleting host '%s'", host.Name)
			derr := s.DeleteHost(host.ID)
			if derr != nil {
				logrus.Warnf("Error deleting host: %v", derr)
			}
		}
	}()

	if host == nil {
		return nil, nil, fmt.Errorf("unexpected nil host")
	}

	if !host.OK() {
		logrus.Warnf("Missing data in host: %v", host)
	}

	return host, userData, nil

}

// Returns true if the error is of type awserr.Error
func isSpecificAWSErr(err error, code string, message string) bool {
	if err, ok := err.(awserr.Error); ok {
		logrus.Warnf("Received AWS error code: %s", err.Code())
		return err.Code() == code && strings.Contains(err.Message(), message)
	}
	return false
}

/*
Returns true if the error matches all these conditions:
- err if of type awserr.Error
- Error.Code() matches code
- Error.Message() contains message
*/
func isAWSErr(err error) bool {
	if err, ok := err.(awserr.Error); ok {
		logrus.Warnf("Received AWS error code: %s", err.Code())
		return true
	}

	return false
}

func buildAwsMachine(EC2Service *ec2.EC2, name string, imageId string, s3 string, s4 string, s5 string, b bool, template *resources.HostTemplate) (*resources.Host, error) {
	//Run instance
	out, err := EC2Service.RunInstances(&ec2.RunInstancesInput{
		ImageId:      aws.String(imageId),
		KeyName:      aws.String(name),
		InstanceType: aws.String(template.ID),
		MaxCount:     aws.Int64(1),
		MinCount:     aws.Int64(1),
		// TagSpecifications: []*ec2.TagSpecification{
		// 	{
		// 		Tags: []*ec2.Tag{
		// 			{
		// 				Key:   aws.String("Name"),
		// 				Value: aws.String(request.Name),
		// 			},
		// 		},
		// 	},
		// },
	})
	if err != nil {
		if isAWSErr(err) {
			return nil, err
		}
		return nil, err
	}
	instance := out.Instances[0]

	host := resources.Host{
		ID:   aws.StringValue(instance.InstanceId),
		Name: name,
	}
	return &host, nil
}

func (s *Stack) InspectHost(interface{}) (*resources.Host, error) {
	panic("implement me") // FIXME Technical debt
}

func (s *Stack) GetHostByName(string) (*resources.Host, error) {
	panic("implement me") // FIXME Technical debt
}

func (s *Stack) GetHostState(interface{}) (HostState.Enum, error) {
	panic("implement me") // FIXME Technical debt
}

func (s *Stack) ListHosts() ([]*resources.Host, error) {
	var hosts []*resources.Host

	dio, err := s.EC2Service.DescribeInstances(&ec2.DescribeInstancesInput{})
	if err != nil {
		return hosts, err
	}

	for _, reservation := range dio.Reservations {
		if reservation != nil {
			for _, instance := range reservation.Instances {
				if instance != nil {
					state, _ := getState(instance.State)
					hosts = append(hosts, &resources.Host{
						ID:         aws.StringValue(instance.InstanceId),
						Name:       "",
						LastState:  state,
						Properties: nil, // FIXME Problems here
					})
				}
			}
		}
	}

	return hosts, nil
}

func (s *Stack) DeleteHost(id string) error {
	ips, err := s.EC2Service.DescribeAddresses(&ec2.DescribeAddressesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String("instance-id"),
				Values: []*string{aws.String(id)},
			},
		},
	})
	if err != nil {
		if ips != nil {
			for _, ip := range ips.Addresses {
				_, _ = s.EC2Service.ReleaseAddress(&ec2.ReleaseAddressInput{
					AllocationId: ip.AllocationId,
				})
			}
		}
	}
	_, err = s.EC2Service.TerminateInstances(&ec2.TerminateInstancesInput{
		InstanceIds: []*string{aws.String(id)},
	})
	return err
}

func (s *Stack) StopHost(id string) error {
	_, err := s.EC2Service.StopInstances(&ec2.StopInstancesInput{
		Force:       aws.Bool(true),
		InstanceIds: []*string{aws.String(id)},
	})
	return err
}

func (s *Stack) StartHost(id string) error {
	_, err := s.EC2Service.StartInstances(&ec2.StartInstancesInput{
		InstanceIds: []*string{aws.String(id)},
	})
	return err
}

func (s *Stack) RebootHost(id string) error {
	_, err := s.EC2Service.RebootInstances(&ec2.RebootInstancesInput{
		InstanceIds: []*string{aws.String(id)},
	})
	return err
}

func (s *Stack) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	panic("implement me") // FIXME Technical debt
}
