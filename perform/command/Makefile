GO?=go
EXEC:=perform

.PHONY:	$(EXEC) clean

all:	$(EXEC)

$(EXEC):	main.go cmd/*.go #../utils/*.go #../broker.pb.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC)
