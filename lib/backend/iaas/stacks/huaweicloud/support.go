package huaweicloud

import "net/http"

func closer(hr *http.Response) {
	if hr != nil {
		if hr.Body != nil {
			_ = hr.Body.Close()
		}
	}
}
