GO?=go
EXEC:=safescale

.PHONY:	safescale clean

all:	safescale

vet:
	@$(GO) vet ./...

safescale:
	@$(GO) build -race -o $(EXEC) $(BUILD_TAGS)

clean:
	@$(RM) $(EXEC) || true
