GO      = go
GOFLAGS = -trimpath -ldflags="-s -extldflags=-static" -tags=netgo,osusergo

build: opalctl opalpba

opalctl:
	$(GO) build $(GOFLAGS)
.PHONY: opalctl

opalpba:
	$(GO) build $(GOFLAGS)
.PHONY: opalpba

clean:
	$(RM) opalctl opalpba
