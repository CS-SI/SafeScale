package listeners

import (
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func getUserMessage(err error) string {
	if err == nil {
		return ""
	}

	if fail.ImplementsCauser(err) {
		return fail.Message(err)
	}

	return err.Error()
}

func adaptedUserMessage(err error) string {
	if err == nil {
		return ""
	}

	adapted := getUserMessage(err)

	if len(adapted) > 0 {
		adapted = ": " + adapted
	}

	return adapted
}
