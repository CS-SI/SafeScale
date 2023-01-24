package rscapi

// FeatureSettings are used to tune the feature
type FeatureSettings struct {
	SkipProxy               bool // to tell not to try to set reverse proxy
	Serialize               bool // force not to parallel hosts in step
	SkipFeatureRequirements bool // tells not to install required features
	SkipSizingRequirements  bool // tells not to check sizing requirements
	AddUnconditionally      bool // tells to not check before addition (no effect for check or removal)
	IgnoreSuitability       bool // allows to not check if the feature is suitable for the target
}
