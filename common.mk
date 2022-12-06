VERSION=22.11.1
export VERSION

ifeq ($(MAKE_LEVEL),)
MAKE_LEVEL=1
MAKE_TRACE=""
else
MAKE_LEVEL+=1
MAKE_TRACE=$(shell printf '    %.0s' {1..$(MAKE_LEVEL)})
endif
export MAKE_LEVEL

ifndef VERBOSE
MAKEFLAGS += --no-print-directory
endif

ifneq (, $(GOOS))
ifneq (, $(GOARCH))
ifneq (, $(GOBIN))
$(error "Cross compilation cannot work with GOBIN defined. Stopping build.")
endif
endif
endif

ifneq (, $(GOOS))
ifeq (, $(GOARCH))
$(error "Cross compilation requires both GOOS and GOARCH to be specified. Stopping build.")
endif
endif

ifeq (, $(GOOS))
ifneq (, $(GOARCH))
$(error "Cross compilation requires both GOOS and GOARCH to be specified. Stopping build.")
endif
endif

ifneq (, $(GOTESTTAGS))
GO_TEST_TAGS=-tags $GOTESTTAGS
else
GO_TEST_TAGS=
endif

ifeq (, $(GOOS))
RACE_CHECK=-race
RACE_CHECK_TEST=-race
else
RACE_CHECK=
RACE_CHECK_TEST=-race
endif

BRANCH_NAME?="develop"

GO?=go
GOFMT?=gofmt
CP?=cp
RM?=rm
MV?=mv
MD5=md5sum
BROWSER?=firefox
GREP?=grep
EGREP?=egrep
CAT?=cat
TAIL?=tail
CUT?=cut
AWK?=awk
SED?=sed
TEE?=tee
EXT?=
WHICH?=which
CERR?=hardened

ifeq ($(OS),Windows_NT)
EXT=.exe
WHICH=where
endif

ifeq (, $(shell $(WHICH) $(GREP)))
$(error "No grep in your PATH: [$(PATH)], you must have grep installed and available through your PATH")
endif

ifeq (, $(shell $(WHICH) $(CAT)))
$(error "No cat in your PATH: [$(PATH)], you must have cat installed and available through your PATH")
endif

ifeq (, $(shell $(WHICH) $(TEE)))
$(error "No tee in your PATH: [$(PATH)], you must have tee installed and available through your PATH")
endif

ifneq ($(OS),Windows_NT)
ifeq (, $(shell $(WHICH) $(EGREP)))
$(error "No egrep in your PATH: [$(PATH)], you must have egrep installed and available through your PATH")
endif
endif

ifeq ($(OS),Windows_NT)
HOME := $(shell printf "%b" "$(HOME)" 2>/dev/null | tr '\' '/' > .tmpfile 2>/dev/null && $(CAT) .tmpfile && $(RM) .tmpfile)
ifeq (, $(shell $(WHICH) rm))
RM = del /Q
endif
endif

ifeq ($(OS),Windows_NT)
ifeq (, $(shell $(WHICH) make))
MAKE=mingw32-make.exe
else
MAKE=make.exe
endif
else
MAKE=make
endif

GOPATH?=$(HOME)/go
GOBIN?=$(GOPATH)/bin
CIBIN?=/tmp

ifneq ($(OS),Windows_NT)
ARCH_DETECTS_RACES=$(shell $(GO) test -race ./lib/utils/empty 2>&1 | egrep -c "ok")

ifeq ($(ARCH_DETECTS_RACES),1)
RACE_CHECK=-race
RACE_CHECK_TEST=-race
else
RACE_CHECK=
RACE_CHECK_TEST=
endif
endif

ifeq (, $(shell $(WHICH) git))
$(error "No git in your PATH: [$(PATH)], you must have git installed and available through your PATH")
endif

ifeq (, $(GOPATH))
$(error "No GOPATH defined")
endif

# Handling multiple gopath: use ~/go by default
ifneq ($(OS),Windows_NT)
ifeq ($(findstring :,$(GOBIN)),:)
GOBIN=$(shell $(GO) env GOBIN | cut -d: -f1)
endif
else
GOBIN=$(shell printf "%b" "$(GOPATH)/bin" 2>/dev/null | tr '\' '/' > .tmpfile 2>/dev/null && $(CAT) .tmpfile && $(RM) .tmpfile)
endif

# Handling multiple gopath: use $(HOME)/go by default
ifneq ($(OS),Windows_NT)
ifeq ($(findstring :,$(GOPATH)),:)
ifeq (, $(GOMODPATH))
$(error "Having a GOPATH with several directories is not recommended, when you have such a GOPATH: [$(GOPATH)], you must specify where your go modules are installed; by default the build looks for modules in 'GOMODPATH/pkg/mod' directory, so you must export the GOMODPATH variable before running the build")
endif
else
GOMODPATH?=$(GOPATH)
endif
endif

ifeq ($(OS),Windows_NT)
ifeq ($(findstring ;,$(GOPATH)),;)
ifeq (, $(GOMODPATH))
$(error "Having a GOPATH with several directories is not recommended, when you have such a GOPATH: [$(GOPATH)], you must specify where your go modules are installed; by default the build looks for modules in 'GOMODPATH/pkg/mod' directory, so you must export the GOMODPATH variable before running the build")
endif
else
GOMODPATH?=$(GOPATH)
endif
endif

ifeq ($(strip $(GOPATH)),)
GOMODPATH?=$(HOME)/go
endif

ifneq ($(OS),Windows_NT)
PATH = $(HOME)/.local/bin:/go/bin:$(shell printenv PATH)
endif

# Life is better with colors
COM_COLOR   = \033[0;34m
OBJ_COLOR   = \033[0;36m
OK_COLOR    = \033[0;32m
GOLD_COLOR  = \033[0;93m
ERROR_COLOR = \033[0;31m
WARN_COLOR  = \033[0;33m
NO_COLOR    = \033[m

OK_STRING    = "[OK]"
INFO_STRING  = "[INFO]"
ERROR_STRING = "[ERROR]"
WARN_STRING  = "[WARNING]"
