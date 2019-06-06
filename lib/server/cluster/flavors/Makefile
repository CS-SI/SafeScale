GO?=go

.PHONY: boh dcos k8s ohpc swarm tests clean

all: boh dcos k8s ohpc swarm

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
