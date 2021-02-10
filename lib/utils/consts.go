package utils

const (
	BaseFolder  = "/opt/safescale"     // is the path of the base folder containing safescale data on cloud provider instances
	BinFolder   = BaseFolder + "/bin"  // is the path of the folder containing safescale binaries on cloud provider instances
	VarFolder   = BaseFolder + "/var"  // is the path of the folder containing safescale equivalent of /var
	LogFolder   = VarFolder + "/log"   // is the path of the folder containing safescale logs
	TempFolder  = VarFolder + "/tmp"   // is the path of the folder containing safescale temporary files
	StateFolder = VarFolder + "/state" // is the path of the folder containing safescale states
)
