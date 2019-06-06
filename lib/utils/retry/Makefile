GO?=go
  
.PHONY: generate clean

all:    generate

vet:
	@$(GO) vet ./...

generate:
	@$(GO) generate ./...

clean:
	@$(RM) ./Verdict/enum_string.go || true

