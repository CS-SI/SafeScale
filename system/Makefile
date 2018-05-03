all: build nfs

build: *.go scripts/*
	go generate

.PHONY: nfs clean

nfs:
	@(cd nfs && $(MAKE) $@)

clean:
	@(cd nfs && $(MAKE))
	@rm -f rice-box.go

