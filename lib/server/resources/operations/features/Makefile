include ../../../../../common.mk

.PHONY:  clean generate vet

all: generate

vet:
	@$(GO) vet ./...

generate:
	@$(GO) generate -run rice

clean:
	@$(RM) rice-box.go || true
