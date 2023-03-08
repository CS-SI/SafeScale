package iaas

var Sections = []string{
	"metadata",
	"objectstorage",
	"compute",
	"network",
	"identity",
	"name",
	"Name",
	"client",
	"Client",
	"provider",
}

var IdentityField = []string{
	"AccessKey",
	"ApplicationKey",
	"OpenstackID",
	"OpenstackPassword",
	"Password",
	"SecretKey",
	"SecretAccessKey",
	"Username",
	"User",
	"UserID",
	"AlternateApiApplicationKey",
	"AlternateApiApplicationSecret",
	"AlternateApiConsumerKey",
	"AccessKeyID",
	"ProjectID",
	"DomainName",
	"DomainID",
	"IdentityEndpoint",
	"TokenID",
	"Endpoint",
	"provider",
	"IdentityEndpointVersion",

	// Google specific
	"ProjectNumber",
	"project_id",
	"private_key_id",
	"private_key",
	"client_email",
	"client_id",
	"auth_uri",
	"token_uri",
	"auth_provider_x509_cert_url",
	"client_x509_cert_url",
}

var computeField = []string{
	"DefaultImage",
	"Domain",
	"DomainName",
	"ProjectName",
	"ProjectID",
	"Region",
	"Subregion",
	"AvailabilityZone",
	"DNS",
	"Scannable",
	"OperatorUsername",
	"Owners",
	"Zone",
	"OperatorUsername",
	"DefaultVolumeSpeed",
	"Service",
	"WhitelistTemplateRegexp",
	"BlacklistTemplateRegexp",
	"DNSList",
	"S3",
	"EC2",
	"SSM",
	"MaxLifetimeInHours",
	"Safe",
	"ConcurrentMachineCreationLimit",
	"TenantName",
	"TenantID",
	"URL",
	"Service",
	"DefaultTenancy",
	"ComputeEndpointVersion",
	"VolumeEndpointVersion",
}

var Networkfield = []string{
	"ProviderNetwork",
	"VPCCIDR",
	"VPCName",
	"FloatingIPPool",
	"DefaultNetworkName",
	"DefaultNetworkCIDR",
	"ExternalNetwork",
	"NetworkEndpointVersion",
	"NetworkClientEndpointVersion",
}

var OStorageField = []string{
	"AccessKey",
	"AuthURL",
	"Domain",
	"DomainName",
	"Endpoint",
	"OpenstackPassword",
	"OpenstackID",
	"ProjectID",
	"ProjectName",
	"Password",
	"Region",
	"AvailabilityZone",
	"SecretKey",
	"SecretAccessKey",
	"Tenant",
	"Type",
	"Username",
	"ApplicationKey",
	"Suffix",
}

var MetadataField = []string{
	"AccessKey",
	"AuthURL",
	"DomainName",
	"Endpoint",
	"Domain",
	"OpenstackPassword",
	"ProjectID",
	"ProjectName",
	"Password",
	"Region",
	"AvailabilityZone",
	"SecretKey",
	"SecretAccessKey",
	"Tenant",
	"Type",
	"Username",
	"CryptKey",
	"MetadataBucketName",
	"Suffix",
	"Bucket",
}
