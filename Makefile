CLIENT_SOURCE=./cmd/ligoloc
SERVER_SOURCE=./cmd/ligolos

CLIENT_BINARY=ligoloc
SERVER_BINARY=ligolos

GCFLAGS="all=-trimpath=$GOPATH"
LDFLAGS="-s -w"

OSARCH = "linux/amd64 windows/amd64"

.DEFAULT: help

help: ## Show Help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

gen: ## Regenerate obfuscated string tables (rotates keys)
	go run ./_strgen

build: ## Build, strip buildinfo and scrub module metadata (current OS)
	go run ./_strgen
	go build -trimpath -buildvcs=false -ldflags $(LDFLAGS) -gcflags $(GCFLAGS) -o bin/$(CLIENT_BINARY) $(CLIENT_SOURCE) && \
	go build -trimpath -buildvcs=false -ldflags $(LDFLAGS) -gcflags $(GCFLAGS) -o bin/$(SERVER_BINARY) $(SERVER_SOURCE) && \
	go run ./_strip bin/$(CLIENT_BINARY) bin/$(SERVER_BINARY)

build-linux: ## Build linux/amd64 (cross), strip and scrub
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags $(LDFLAGS) -o bin/$(CLIENT_BINARY)_linux_amd64 $(CLIENT_SOURCE) && \
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags $(LDFLAGS) -o bin/$(SERVER_BINARY)_linux_amd64 $(SERVER_SOURCE) && \
	go run ./_strip bin/$(CLIENT_BINARY)_linux_amd64 bin/$(SERVER_BINARY)_linux_amd64

clean:
	rm -f bin/*
