package iaas

var Sections = []string{
	"metadata",
	"objectstorage",
	"compute",
	"network",
	"identity",
	"name",
	"client",
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
}

var Networkfield = []string{
	"ProviderNetwork",
	"VPCCIDR",
	"VPCName",
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
}
