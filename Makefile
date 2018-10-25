# ref: https://vic.demuzere.be/articles/golang-makefile-crosscompile/
BIN_DIR := build
BIN_NAME := godoh

K := $(shell openssl rand -hex 16)
V := $(shell git rev-parse --short HEAD)
LD_FLAGS := -s -w -X=github.com/sensepost/godoh/cmd.Version=$(V)

default: keywarn clean darwin linux windows pack integrity

clean:
	$(RM) $(BIN_DIR)/$(BIN_NAME)*
	go clean -x

keywarn:
	@echo "!!! Consider running 'make key' before 'make' to generate new encryption keys!"
	@echo "!!! Not doing this will leave your C2 using the default key!\n"

key:
	sed -i -E "s/const.*/const cryptKey = \`$(K)\`/g" utils/key.go

install:
	go install

darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LD_FLAGS)" -o '$(BIN_DIR)/$(BIN_NAME)-darwin64'

linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LD_FLAGS)" -o '$(BIN_DIR)/$(BIN_NAME)-linux64'

windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LD_FLAGS)" -o '$(BIN_DIR)/$(BIN_NAME)-windows64.exe'
	GOOS=windows GOARCH=386 go build -ldflags="$(LD_FLAGS)" -o '$(BIN_DIR)/$(BIN_NAME)-windows32.exe'

pack:
	cd $(BIN_DIR) && upx $(BIN_NAME)-linux64 $(BIN_NAME)-windows32.exe $(BIN_NAME)-windows64.exe

integrity:
	cd $(BIN_DIR) && shasum *
