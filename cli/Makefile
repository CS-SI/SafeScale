GO?=go

.PHONY:	safescale safescaled clean vet

all:	safescale safescaled

vet:
	@(cd safescale && $(MAKE) $@)
	@(cd safescaled && $(MAKE) $@)
	@(cd scanner && $(MAKE) $@)
	@(cd perform && $(MAKE) $@)

safescale:
	@(cd safescale && $(MAKE))

safescaled:
	@(cd safescaled && $(MAKE))

scanner:
	@(cd safescale && $(MAKE))

perform:
	@(cd safescaled && $(MAKE))

clean:
	@(cd safescale && $(MAKE) $@)
	@(cd safescaled && $(MAKE) $@)
	@(cd scanner && $(MAKE) $@)
	@(cd perform && $(MAKE) $@)
