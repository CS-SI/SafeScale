GO?=go

.PHONY:  clean generate vet

all: generate

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

generate:
	@$(GO) generate -run rice
	@(cd enums && $(MAKE) $(@))

clean:
	@$(RM) rice-box.go enums/*/enum_string.go
