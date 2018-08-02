GO?=go

.PHONY: nfs clean

all: build nfs

build: *.go scripts/*
	@$(GO) generate

vet:
	@$(GO) vet

nfs:
	@(cd nfs && $(MAKE))

clean:
	@(cd nfs && $(MAKE) $@)
	@$(RM) rice-box.go

