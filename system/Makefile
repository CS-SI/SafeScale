GO?=go

all: build nfs

build: *.go scripts/*
	@$(GO) generate

.PHONY: nfs clean

nfs:
	@(cd nfs && $(MAKE))

clean:
	@(cd nfs && $(MAKE) $@)
	@$(RM) rice-box.go

