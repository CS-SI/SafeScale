package listeners

import (
    "github.com/CS-SI/SafeScale/lib/utils/scerr"
)

func getUserMessage(err error) string {
    if err == nil {
        return ""
    }

    if scerr.ImplementsCauser(err) {
        return scerr.Message(err)
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
