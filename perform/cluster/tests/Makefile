all: create_cluster

.PHONY: api dcos tests clean mrproper

create_cluster: create_cluster.go ../api/*.go ../dcos/*.go ../*.go

	@(go generate && go build $<)

clean:
	@(rm -f deploy)

mrproper: clean
	@(rm -f debug)

