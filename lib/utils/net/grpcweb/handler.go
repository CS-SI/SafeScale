package grpcweb

import (
	"net/http"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"
)

type Mux struct {
	*grpcweb.WrappedGrpcServer
}

func NewHandler(grpcServer *grpc.Server, opts ...grpcweb.Option) (*Mux, fail.Error) {
	if grpcServer == nil {
		return nil, fail.InvalidParameterCannotBeNilError("grpcServer")
	}

	m := &Mux{grpcweb.WrapServer(grpcServer, opts...)}
	return m, nil
}

func (m *Mux) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			m.ServeHTTP(w, r)
			return
		}

		if m.IsGrpcWebRequest(r) || m.IsAcceptableGrpcCorsRequest(r) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-User-Agent, X-Grpc-Web")
			w.Header().Set("grpc-status", "")
			w.Header().Set("grpc-message", "")
			m.ServeHTTP(w, r)
			return
		}

		if next != nil {
			next.ServeHTTP(w, r)
		}
	})
}
