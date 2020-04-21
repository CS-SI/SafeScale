GO?=go

.PHONY: clean generate boh k8s tests vet

all: boh k8s

generate:
	@(cd boh && $(MAKE) $@)
	@(cd k8s && $(MAKE) $@)

vet:
	@$(GO) vet ./...

boh:
	@(cd boh && $(MAKE) $(@))

k8s:
	@(cd k8s && $(MAKE) $(@))

tests: boh dcos k8s ohpc swarm
	@(cd tests && $(MAKE) $(@))

clean:
	@(cd boh && $(MAKE) $(@))
	@(cd k8s && $(MAKE) $(@))
