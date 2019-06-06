all: create_cluster

GO?=go

.PHONY: api dcos tests clean mrproper

create_cluster: create_cluster.go ../api/*.go ../flavors/dcos/*.go ../flavors/boh/*.go ../*.go
	@($(GO) generate && $(GO) build $<)

clean:
	@($(RM) -f deploy || true)
	@($(RM) create_cluster || true)

mrproper: clean
	@($(RM) -f debug || true)

