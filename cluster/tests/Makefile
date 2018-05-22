all: deploy

.PHONY: api dcos tests clean mrproper

deploy: deploy.go ../api/*.go ../dcos/*.go ../*.go

	@(go generate && go build $<)

clean:
	@(rm -f deploy)

mrproper: clean
	@(rm -f debug)

