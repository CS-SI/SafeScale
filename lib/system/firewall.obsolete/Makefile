GO?=go

.PHONY:	generate clean vet

all:	generate

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

DIRECTORIES := $(sort $(dir $(wildcard */)))

generate:
	@$(GO) generate $(BUILD_TAGS) ./...

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(RM) *_string.go || true); done)