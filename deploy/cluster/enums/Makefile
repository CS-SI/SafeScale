GO?=go

.PHONY: all

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

vet:
	@$(GO) vet ./...

generate:
	@$(GO) generate ./...

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(RM) *_string.go || true); done)

