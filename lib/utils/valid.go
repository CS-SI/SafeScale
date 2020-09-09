package utils

//go:generate mockgen -destination=../mocks/mock_valid.go -package=mocks github.com/CS-SI/SafeScale/lib/utils Valid

// Valid interface is used to check data validity
type Valid interface {
	OK() bool
}
