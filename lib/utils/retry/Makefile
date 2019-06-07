GO?=go
  
.PHONY: clean generate vet

all:    generate

generate:
	@(cd enums && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

clean:
	@$(RM) ./enums/Verdict/enum_string.go || true

