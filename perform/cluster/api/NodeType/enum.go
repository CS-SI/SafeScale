package NodeType

//go:generate stringer -type=Enum

//Enum represents the type of a node
type Enum int

const (
	//Bootstrap to represent a bootstrap node
	Bootstrap Enum = iota
	//Master to represent a master node
	Master
	//PrivateAgent to represent a private agent
	PrivateAgent
	//PublicAgent to represent a public agent
	PublicAgent
)
