package SecurityFlavor

//go:generate stringer -type=Enum

//Enum represents the state of a node
type Enum int

const (
	//Sys indicates the default no-cryptographic security
	Sys Enum = iota
	//Krb5 indicates Kerberos5 authentication only
	Krb5
	//Krb5i indicates Kerberos5 with integrity protection
	Krb5i
	//Krb5p indicates Kerberos5 with privacy protection
	Krb5p
)
