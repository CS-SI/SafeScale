GO?=go

.PHONY: all vet generate clean

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

generate:
	@$(GO) generate $(BUILD_TAGS) ./...

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(RM) *_string.go || true); done)

