build:
	go build -trimpath -ldflags="-s -extldflags=-static" -tags=netgo,osusergo
