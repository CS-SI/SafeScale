package api

// WrappedProvider ...
type WrappedProvider struct {
	InnerProvider Provider
	Name          string
}
