package huaweicloud

import (
	"context"
	"net/http"
)

func closer(hr *http.Response) {
	if hr != nil {
		if hr.Body != nil {
			_ = hr.Body.Close()
		}
	}
}

func cleanupContextFrom(inctx context.Context) context.Context {
	if oldKey := inctx.Value("ID"); oldKey != nil {
		ctx := context.WithValue(context.Background(), "ID", oldKey) // nolint
		// cleanup functions can look for "cleanup" to decide if a ctx is a cleanup context
		ctx = context.WithValue(ctx, "cleanup", true) // nolint
		return ctx
	}
	return context.Background()
}
