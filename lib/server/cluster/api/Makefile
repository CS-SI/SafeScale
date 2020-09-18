
GO?=go

.PHONY: vet generate clean

all: generate

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

generate:
	@$(GO) generate $(BUILD_TAGS) ./...

clean: ;

