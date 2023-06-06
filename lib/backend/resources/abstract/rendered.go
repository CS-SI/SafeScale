package abstract

type RenderedContent struct {
	Name     string `json:"Name"`
	Content  string `json:"Content"`
	Complete bool   `json:"Complete"`
}
