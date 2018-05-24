GO?=go

all: build

build: *.go scripts/* SecurityFlavor/*.go
	@(cd SecurityFlavor && $(GO) generate)
	@$(GO) generate

.PHONY: nfs clean

clean:
	@$(RM) rice-box.go SecurityFlavor/enum_string.go
