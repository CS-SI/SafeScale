package aws

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ssm"
)

type Stack struct {
	Config      *stacks.ConfigurationOptions
	AuthOptions *stacks.AuthenticationOptions
	AwsConfig   *stacks.AWSConfiguration

	S3Service      *s3.S3
	EC2Service     *ec2.EC2
	SSMService     *ssm.SSM
	PricingService *pricing.Pricing
}

func (s *Stack) CreateVIP(string, string) (*resources.VIP, error) {
	panic("implement me") // FIXME Technical debt
}

func (s *Stack) AddPublicIPToVIP(*resources.VIP) error {
	panic("implement me") // FIXME Technical debt
}

func (s *Stack) BindHostToVIP(*resources.VIP, *resources.Host) error {
	panic("implement me") // FIXME Technical debt
}

func (s *Stack) UnbindHostFromVIP(*resources.VIP, *resources.Host) error {
	panic("implement me") // FIXME Technical debt
}

func (s *Stack) DeleteVIP(*resources.VIP) error {
	panic("implement me") // FIXME Technical debt
}

// FIXME Orphan method
func (s *Stack) GetConfigurationOptions() stacks.ConfigurationOptions {
	return *s.Config
}

// FIXME Orphan method
func (s *Stack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return *s.AuthOptions
}

// FIXME Orphan method
// New Create and initialize a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.AWSConfiguration, cfg stacks.ConfigurationOptions) (*Stack, error) {
	stack := &Stack{
		Config:      &cfg,
		AuthOptions: &auth,
		AwsConfig:   &localCfg,
	}

	// FIXME Validate region against endpoints.UsWest2RegionID // UsWest2RegionID      = "us-west-2"      // US West (Oregon).

	userId := auth.Username
	secretKey := auth.SecretAccessKey

	s := session.Must(session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials(userId, secretKey, ""),
		S3ForcePathStyle: aws.Bool(true),
		Region:           aws.String(localCfg.Region),
		Endpoint:         aws.String(localCfg.S3Endpoint),
	}))

	sec2 := session.Must(session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials(userId, secretKey, ""),
		S3ForcePathStyle: aws.Bool(true),
		Region:           aws.String(localCfg.Region),
		Endpoint:         aws.String(localCfg.Ec2Endpoint),
	}))

	sssm := session.Must(session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials(userId, secretKey, ""),
		S3ForcePathStyle: aws.Bool(true),
		Region:           aws.String(localCfg.Region),
		Endpoint:         aws.String(localCfg.SsmEndpoint),
	}))

	spricing := session.Must(session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials(userId, secretKey, ""),
		S3ForcePathStyle: aws.Bool(true),
		Region:           aws.String(endpoints.UsEast1RegionID),
	}))

	stack.S3Service = s3.New(s, &aws.Config{})
	stack.EC2Service = ec2.New(sec2, &aws.Config{})
	stack.SSMService = ssm.New(sssm, &aws.Config{})
	stack.PricingService = pricing.New(spricing, &aws.Config{})

	// FIXME Populate things here

	return stack, nil
}

func (s *Stack) CreateKeyPair(name string) (*resources.KeyPair, error) {
	publicKey, privateKey, err := system.CreateKeyPair()
	if err != nil {
		return nil, err
	}
	_, err = s.EC2Service.ImportKeyPair(&ec2.ImportKeyPairInput{
		KeyName:           aws.String(name),
		PublicKeyMaterial: publicKey,
	})
	if err != nil {
		return nil, err
	}
	return &resources.KeyPair{
		ID:         name,
		Name:       name,
		PrivateKey: string(privateKey),
		PublicKey:  string(publicKey),
	}, nil
}

func (s *Stack) GetKeyPair(id string) (*resources.KeyPair, error) {
	out, err := s.EC2Service.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{
		KeyNames: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	if len(out.KeyPairs) == 0 {
		return nil, fmt.Errorf("no keypairs found")
	}

	kp := out.KeyPairs[0]
	return &resources.KeyPair{
		ID:         aws.StringValue(kp.KeyName),
		Name:       aws.StringValue(kp.KeyName),
		PrivateKey: "",
		PublicKey:  aws.StringValue(kp.KeyFingerprint),
	}, nil

}

func (s *Stack) ListKeyPairs() ([]resources.KeyPair, error) {
	out, err := s.EC2Service.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{})
	if err != nil {
		return nil, err
	}
	var keys []resources.KeyPair
	for _, kp := range out.KeyPairs {
		keys = append(keys, resources.KeyPair{
			ID:         aws.StringValue(kp.KeyName),
			Name:       aws.StringValue(kp.KeyName),
			PrivateKey: "",
			PublicKey:  aws.StringValue(kp.KeyFingerprint),
		})

	}
	return keys, nil
}

func (s *Stack) DeleteKeyPair(id string) error {
	_, err := s.EC2Service.DeleteKeyPair(&ec2.DeleteKeyPairInput{
		KeyName: aws.String(id),
	})
	return err
}

func (s *Stack) CreateGateway(req resources.GatewayRequest) (*resources.Host, *userdata.Content, error) {
	panic("implement me") // FIXME Technical debt
}

func (s *Stack) DeleteGateway(networkID string) error {
	panic("implement me") // FIXME Technical debt
}

func getState(state *ec2.InstanceState) (HostState.Enum, error) {
	// The low byte represents the state. The high byte is an opaque internal value
	// and should be ignored.
	//
	//    * 0 : pending
	//
	//    * 16 : running
	//
	//    * 32 : shutting-down
	//
	//    * 48 : terminated
	//
	//    * 64 : stopping
	//
	//    * 80 : stopped
	fmt.Println("State", state.Code)
	if state == nil {
		return HostState.ERROR, fmt.Errorf("unexpected host state")
	}
	if *state.Code == 0 {
		return HostState.STARTING, nil
	}
	if *state.Code == 16 {
		return HostState.STARTED, nil
	}
	if *state.Code == 32 {
		return HostState.STOPPING, nil
	}
	if *state.Code == 48 {
		return HostState.STOPPED, nil
	}
	if *state.Code == 64 {
		return HostState.STOPPING, nil
	}
	if *state.Code == 80 {
		return HostState.STOPPED, nil
	}
	return HostState.ERROR, fmt.Errorf("unexpected host state")
}
