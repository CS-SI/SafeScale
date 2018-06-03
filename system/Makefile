GO?=go

all: build nfs vet

build: *.go scripts/*
	@$(GO) generate
vet:
	@$(GO) vet

.PHONY: nfs clean

nfs:
	@(cd nfs && $(MAKE))

clean:
	@(cd nfs && $(MAKE) $@)
	@$(RM) rice-box.go

