GO?=go

.PHONY: clean generate boh k8s vet

all: boh k8s

generate: clean
	@(cd boh && $(MAKE) $@)
	@(cd k8s && $(MAKE) $@)

vet:
	@$(GO) vet ./...

boh:
	@(cd boh && $(MAKE))

k8s:
	@(cd k8s && $(MAKE))

clean:
	@(cd boh && $(MAKE) $@)
	@(cd k8s && $(MAKE) $@)
