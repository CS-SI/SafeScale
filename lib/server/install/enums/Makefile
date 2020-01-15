GO?=go

.PHONY:	clean generate vet 

all:	generate 

vet:
	@($(GO) vet ./...)

generate: clean
	@$(GO) generate -run stringer ./...

clean:
	@($(RM) */enum_string.go || true)
