package providers

// WrappedProvider ...
type WrappedProvider struct {
	InnerProvider Provider
	Name          string
}
