package providers

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type (
	// StackReservedForProviderUse is an interface about the methods only available to providers internally
	StackReservedForProviderUse interface {
		ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error)           // list available OS images
		ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) // list available host templates
		ConfigurationOptions() (iaasoptions.Configuration, fail.Error)                      // Return a read-only struct containing configuration options
		AuthenticationOptions() (iaasoptions.Authentication, fail.Error)                    // Return a read-only struct containing authentication options
		HasDefaultNetwork() (bool, fail.Error)                                              // return true if the stack as a default network set (coming from tenants file)
		DefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error)                 // return the *abstract.Network corresponding to the default network
	}

	ReservedForTerraformerUse interface {
		// TerraformRenderer(iaasapi.Provider) (terraformerapi.Terraformer, fail.Error)
		ConsolidateNetworkSnippet(*abstract.Network)
		ConsolidateSubnetSnippet(*abstract.Subnet)
		ConsolidateSecurityGroupSnippet(*abstract.SecurityGroup)
		// ConsolidateLabelSnippet(*abstract.Label)
		ConsolidateHostSnippet(*abstract.HostCore)
		ConsolidateVolumeSnippet(*abstract.Volume)
	}
)
