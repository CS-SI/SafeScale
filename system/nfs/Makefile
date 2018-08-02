GO?=go

.PHONY: nfs clean

all: build

vet:
	@$(GO) vet

build: *.go scripts/* SecurityFlavor/*.go
	@(cd SecurityFlavor && $(GO) generate)
	@$(GO) generate

clean:
	@$(RM) rice-box.go SecurityFlavor/enum_string.go
