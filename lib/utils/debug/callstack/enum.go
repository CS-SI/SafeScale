package callstack

//go:generate stringer -type=Enum

// Enum ...
type Enum int

const (
	_ Enum = iota
	FirstOccurrence
	LastOccurrence
)
