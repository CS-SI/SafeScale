VERSION=21.02.0-sizing
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

ifeq (, $(GOOS))
RACE_CHECK=-race
else
RACE_CHECK=
endif

BRANCH_NAME?="develop"
FIRSTUPDATE := $(shell git remote update >/dev/null 2>&1)
BUILD := $(shell git rev-parse HEAD)
UPSTREAM := $(shell git rev-parse origin/$(BRANCH_NAME))
LOCAL := $(shell git rev-parse HEAD)
REMOTE := $(shell git rev-parse $(UPSTREAM))
BASE := $(shell git merge-base HEAD $(UPSTREAM))

GO?=go
GOFMT?=gofmt
CP?=cp
RM?=rm
BROWSER?=firefox
BUILDTOOL?=mod

ifeq ($(OS),Windows_NT)
HOME := $(shell printf "%b" "$(HOME)" 2>/dev/null | tr '\' '/' > .tmpfile 2>/dev/null && cat .tmpfile && $(RM) .tmpfile)
ifeq (, $(shell which rm))
RM = del /Q
endif
endif

ifeq ($(OS),Windows_NT)
MAKE=mingw32-make.exe
endif

GOPATH?=$(HOME)/go
GOBIN?=$(GOPATH)/bin
CIBIN?=/tmp

ifeq (, $(shell which git))
$(error "No git in your PATH: [$(PATH)], you must have git installed and available through your PATH")
endif

ifeq (, $(GOPATH))
$(error "No GOPATH defined")
endif

# Handling multiple gopath: use ~/go by default
ifeq ($(findstring :,$(GOBIN)),:)
# GOBIN=$(HOME)/go/bin
GOBIN=$(shell $(GO) env GOBIN | cut -d: -f1)
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

ifneq ($(OS),Windows_NT)
ifneq ($(findstring $(GOBIN),$(PATH)),$(GOBIN))
$(error "Your 'GOBIN' directory [$(GOBIN)] must be included in your 'PATH' [$(PATH)]")
endif
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
