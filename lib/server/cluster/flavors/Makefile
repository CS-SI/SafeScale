GO?=go

.PHONY: clean generate boh dcos k8s ohpc swarm tests vet

all: boh dcos k8s ohpc swarm

generate:
	@(cd boh && $(MAKE) $@)
	@(cd dcos && $(MAKE) $@)
	@(cd k8s && $(MAKE) $@)
	@(cd ohpc && $(MAKE) $@)
	@(cd swarm && $(MAKE) $@)

vet:
	@$(GO) vet ./...

dcos:
	@(cd dcos && $(MAKE))

boh:
	@(cd boh && $(MAKE))

ohpc:
	@(cd ohpc && $(MAKE))

k8s:
	@(cd k8s && $(MAKE))

swarm:
	@(cd swarm && $(MAKE))

tests: boh dcos k8s ohpc swarm
	@(cd tests && $(MAKE))

clean:
	@(cd boh && $(MAKE) $@)
	@(cd dcos && $(MAKE) $@)
	@(cd k8s && $(MAKE) $@)
	@(cd ohpc && $(MAKE) $@)
	@(cd swarm && $(MAKE) $@)
