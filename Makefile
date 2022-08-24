.DEFAULT_GOAL     := default

GOLANGCI_VERSION  ?= 1.46.2
GOIMPORTS_VERSION ?= v0.1.12

GOFMT_FILES       ?= $$(find ./ -name '*.go' | grep -v vendor)

TIME              ?= 5s


.PHONY: default
default: lint test

.PHONY: test
test:
	@echo "==> Executing tests..."
	@bash -e -o pipefail -c 'go list ./... | xargs -n1 go test --timeout 30m -v -count 1'

.PHONY: fuzz
fuzz:
	@echo "==> Executing fuzz tests..."
	@bash -e -o pipefail -c 'go test -list=. | grep "Fuzz" | xargs -n1 -I@ sh -c "echo \"==> Running @...\"; go test -fuzztime $(TIME) -fuzz @"'

.PHONY: lint
lint: tools/golangci-lint
	@echo "==> Running golangci-lint..."
	@tools/golangci-lint run

.PHONY: goimports
goimports: tools/goimports
	@echo "==> Running goimports..."
	@tools/goimports -w $(GOFMT_FILES)

.PHONY: calculate-next-semver
calculate-next-semver:
	@bash -e -o pipefail -c '(source ./scripts/calculate-next-version.sh && echo $${FULL_TAG}) | tail -n 1'

###########################
# Tools targets
###########################

.PHONY: tools/golangci-lint
tools/golangci-lint:
	@echo "==> Installing golangci-lint..."
	@./scripts/install-golangci-lint.sh $(GOLANGCI_VERSION)

.PHONY: tools/goimports
tools/goimports:
	@echo "==> Installing goimports..."
	@GOBIN=$$(pwd)/tools/ go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
