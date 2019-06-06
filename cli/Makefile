GO?=go

.PHONY:	safescale safescaled perform scanner clean vet

all:	safescale safescaled perform scanner

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
