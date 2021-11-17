MAIN_PACKAGE := contactform-slack
BUILT_ON := $(shell date)
GOOS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
COMMIT_HASH:=$(shell git log -n 1 --pretty=format:"%H")
PACKAGES:=$(shell go list ./... | grep -v /vendor/)
GO_LINUX := GOOS=linux GOARCH=amd64
GO_OSX := GOOS=darwin GOARCH=amd64
GO_WIN := GOOS=darwin GOARCH=amd64
LDFLAGS := '-s -w'

default: build

build:
	GOOS=$(GOOS) CGO_ENABLED=0 go build -a -installsuffix cgo -o $(MAIN_PACKAGE) -ldflags $(LDFLAGS) .

osx:
	CGO_ENABLED=0 $(GO_OSX) go build -a -installsuffix cgo -o $(MAIN_PACKAGE) -ldflags $(LDFLAGS) .

linux:
	CGO_ENABLED=0 $(GO_LINUX) go build -a -installsuffix cgo -o $(MAIN_PACKAGE) -ldflags $(LDFLAGS) .

windows:
	CGO_ENABLED=0 $(GO_WIN) go build -a -installsuffix cgo -o $(MAIN_PACKAGE).exe -ldflags $(LDFLAGS) .

clean:
	find . -name *_gen.go -type f -delete
	rm -f ./$(MAIN_PACKAGE)

fmt:
	go fmt ./...

lint: fmt
	$(GOPATH)/bin/staticcheck $(PACKAGES)
	$(GOPATH)/bin/golangci-lint run
	$(GOPATH)/bin/gosec -quiet -no-fail ./...

run:
	go run main.go

update-deps:
	go get -u ./...
	go mod tidy

certs:
	openssl req -x509 -newkey rsa:4096 -nodes -keyout ./localhost.key -out ./localhost.pem -days 365 -sha256 -subj '/CN=localhost'

dbuild: certs
	sudo docker build . -t perlogix:$(MAIN_PACKAGE)

drun:
	sudo docker rm -f $(MAIN_PACKAGE)
	sudo docker run --name=$(MAIN_PACKAGE) -d -p 127.0.0.1:8080:8080 --env-file ./env-file --restart always perlogix:$(MAIN_PACKAGE)