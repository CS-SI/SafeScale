GO?=go

.PHONY: nfs clean

all: build nfs

build: *.go scripts/*
	@$(GO) generate ./...

vet:
	@$(GO) vet ./...

nfs:
	@(cd nfs && $(MAKE))

clean:
	@(cd firewall && $(MAKE) $@)
	@(cd nfs && $(MAKE) $@)
	@$(RM) rice-box.go || true
