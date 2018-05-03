all: build

build: *.go scripts/*
	@(cd SecurityFlavor && go generate)
	@go generate

.PHONY: nfs clean

clean:
	@rm -f rice-box.go SecurityFlavor/enum_string.go

