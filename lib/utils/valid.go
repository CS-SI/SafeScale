package utils

//go:generate mockgen -destination=../mocks/mock_valid.go -package=mocks github.com/CS-SI/SafeScale/lib/utils Valid

type Valid interface {
	OK() bool
}
