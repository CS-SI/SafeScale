GO?=go

.PHONY:	generate clean vet 

all:	generate 

vet:
	@($(GO) vet ./...)

DIRECTORIES := $(sort $(dir $(wildcard */)))

generate:
	@(mkdir -p mocks) || true
	@$(GO) generate -run stringer ./...

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(RM) *_string.go || true); done)
