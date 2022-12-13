package data

//go:generate minimock -o mocks/mock_validatable.go -i github.com/CS-SI/SafeScale/v22/lib/utils/data.Validatable

// Validatable interface is used to check data validity
type Validatable interface {
	Valid() bool
}
