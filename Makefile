# Makefile for P2P DERP Network and Prysm K8s Agent

# Variables
GO_VERSION := 1.21
REGISTRY := ghcr.io/kubeaccess
PROJECT_NAME := prysm-agent
VERSION := $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse HEAD)
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Default target
.PHONY: all
all: clean test build

# Help target
.PHONY: help
help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development targets
.PHONY: dev-setup
dev-setup: ## Set up development environment
	@echo "Setting up development environment..."
	go mod download
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: deps
deps: ## Download dependencies
	go mod download
	go mod tidy

# Build targets
.PHONY: build
build: build-derp-server build-prysm-agent build-test-clients ## Build all binaries

.PHONY: build-derp-server
build-derp-server: ## Build P2P DERP server
	@echo "Building P2P DERP server..."
	go build $(LDFLAGS) -o bin/derp-server p2p-derp-server.go

.PHONY: build-prysm-agent
build-prysm-agent: ## Build enhanced Prysm K8s agent
	@echo "Building enhanced Prysm K8s agent..."
	go build $(LDFLAGS) -o bin/prysm-agent enhanced-prysm-agent.go

.PHONY: build-test-clients
build-test-clients: ## Build test clients
	@echo "Building test clients..."
	go build -o bin/test-p2p-client test-p2p-client.go
	go build -o bin/saas-test-client saas-test-client.go
	go build -o bin/direct-k8s-test direct-k8s-test.go

.PHONY: build-all-platforms
build-all-platforms: ## Build for multiple platforms
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/derp-server-linux-amd64 p2p-derp-server.go
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/derp-server-linux-arm64 p2p-derp-server.go
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/derp-server-darwin-amd64 p2p-derp-server.go
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/derp-server-darwin-arm64 p2p-derp-server.go
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/derp-server-windows-amd64.exe p2p-derp-server.go
	
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/prysm-agent-linux-amd64 enhanced-prysm-agent.go
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/prysm-agent-linux-arm64 enhanced-prysm-agent.go
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/prysm-agent-darwin-amd64 enhanced-prysm-agent.go
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/prysm-agent-darwin-arm64 enhanced-prysm-agent.go

# Test targets
.PHONY: test
test: test-unit test-integration ## Run all tests

.PHONY: test-unit
test-unit: ## Run unit tests
	@echo "Running unit tests..."
	go test -v -race -coverprofile=coverage.out ./...

.PHONY: test-integration
test-integration: ## Run integration tests with real Docker Compose stack
	@echo "Running integration tests with real K3s clusters..."
	./test/run-integration-tests.sh

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	@echo "Running E2E tests..."
	go test -v -run "TestE2E" -timeout=15m

.PHONY: test-performance
test-performance: ## Run performance tests with real clusters
	@echo "Running performance tests with real clusters..."
	./test/run-integration-tests.sh TestRealPerformance_

.PHONY: test-benchmarks
test-benchmarks: ## Run benchmarks with real clusters
	@echo "Running benchmarks with real clusters..."
	./test/run-integration-tests.sh BenchmarkRealCluster_

.PHONY: test-integration-setup
test-integration-setup: ## Setup integration test environment only
	@echo "Setting up integration test environment..."
	./test/run-integration-tests.sh --setup-only

.PHONY: test-integration-cleanup
test-integration-cleanup: ## Cleanup integration test environment
	@echo "Cleaning up integration test environment..."
	./test/run-integration-tests.sh --cleanup-only

.PHONY: test-integration-verbose
test-integration-verbose: ## Run integration tests with verbose output
	@echo "Running integration tests with verbose output..."
	./test/run-integration-tests.sh -v

.PHONY: test-coverage
test-coverage: test-unit ## Generate test coverage report
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Code quality targets
.PHONY: lint
lint: ## Run linter
	golangci-lint run

.PHONY: fmt
fmt: ## Format code
	gofmt -s -w .
	goimports -w .

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: security
security: ## Run security checks
	govulncheck ./...

.PHONY: quality
quality: fmt vet lint security ## Run all code quality checks

# UI Development targets
.PHONY: ui-install
ui-install: ## Install UI dependencies
	@echo "Installing UI dependencies..."
	cd ui && npm install

.PHONY: ui-dev
ui-dev: ## Start UI development server
	@echo "Starting UI development server..."
	cd ui && npm run dev

.PHONY: ui-build
ui-build: ## Build UI for production
	@echo "Building UI for production..."
	cd ui && npm run build

.PHONY: ui-lint
ui-lint: ## Lint UI code
	@echo "Linting UI code..."
	cd ui && npm run lint

# Docker targets
.PHONY: docker-build
docker-build: docker-build-derp-server docker-build-prysm-agent docker-build-ui ## Build Docker images

.PHONY: docker-build-derp-server
docker-build-derp-server: ## Build DERP server Docker image
	@echo "Building DERP server Docker image..."
	docker build -f Dockerfile.derp-server -t $(REGISTRY)/derp-server:$(VERSION) .
	docker tag $(REGISTRY)/derp-server:$(VERSION) $(REGISTRY)/derp-server:latest

.PHONY: docker-build-prysm-agent
docker-build-prysm-agent: ## Build Prysm K8s agent Docker image
	@echo "Building Prysm K8s agent Docker image..."
	docker build -f Dockerfile -t $(REGISTRY)/prysm-agent:$(VERSION) .
	docker tag $(REGISTRY)/prysm-agent:$(VERSION) $(REGISTRY)/prysm-agent:latest

.PHONY: docker-build-ui
docker-build-ui: ## Build UI Docker image
	@echo "Building UI Docker image..."
	docker build -f Dockerfile.ui -t $(REGISTRY)/kubeaccess-ui:$(VERSION) .
	docker tag $(REGISTRY)/kubeaccess-ui:$(VERSION) $(REGISTRY)/kubeaccess-ui:latest

.PHONY: docker-push
docker-push: ## Push Docker images
	@echo "Pushing Docker images..."
	docker push $(REGISTRY)/derp-server:$(VERSION)
	docker push $(REGISTRY)/derp-server:latest
	docker push $(REGISTRY)/prysm-agent:$(VERSION)
	docker push $(REGISTRY)/prysm-agent:latest

.PHONY: docker-test
docker-test: docker-build ## Test Docker images
	@echo "Testing DERP server Docker image..."
	docker run --rm -d --name test-derp -p 8443:8443 $(REGISTRY)/derp-server:$(VERSION)
	sleep 5
	curl -k https://localhost:8443/health || (docker stop test-derp && exit 1)
	docker stop test-derp
	
	@echo "Testing Prysm K8s agent Docker image..."
	docker run --rm $(REGISTRY)/prysm-agent:$(VERSION) --help

# Kubernetes targets
.PHONY: k8s-deploy
k8s-deploy: ## Deploy to Kubernetes
	@echo "Deploying to Kubernetes..."
	kubectl apply -f manifests/enhanced-agent-deployment.yaml

.PHONY: k8s-undeploy
k8s-undeploy: ## Remove from Kubernetes
	@echo "Removing from Kubernetes..."
	kubectl delete -f manifests/enhanced-agent-deployment.yaml --ignore-not-found

.PHONY: k8s-logs
k8s-logs: ## Show Prysm K8s agent logs
	kubectl logs -l app=kubeaccess-enhanced-agent -n kubeaccess-system --tail=100 -f

.PHONY: k8s-status
k8s-status: ## Show K8s deployment status
	kubectl get pods,svc,deploy -n kubeaccess-system

# Demo targets
.PHONY: demo-setup
demo-setup: build ## Set up demo environment
	@echo "Setting up demo environment..."
	./scripts/demo-setup.sh

.PHONY: demo-run
demo-run: ## Run demo
	@echo "Running demo..."
	./scripts/demo-run.sh

.PHONY: demo-cleanup
demo-cleanup: ## Clean up demo environment
	@echo "Cleaning up demo..."
	./scripts/demo-cleanup.sh

# Development workflow targets
.PHONY: dev-derp-server
dev-derp-server: build-derp-server ## Run DERP server in development mode
	@echo "Starting DERP server in development mode..."
	./bin/derp-server us-east 8443

.PHONY: dev-prysm-agent
dev-prysm-agent: build-prysm-agent ## Run Prysm K8s agent in development mode
	@echo "Starting Prysm K8s agent in development mode..."
	CLUSTER_ID=dev-cluster \
	REGION=dev-region \
	DERP_SERVERS=wss://localhost:8443/derp \
	AGENT_TOKEN=dev-token \
	BACKEND_URL=https://dev-backend.com \
	./bin/prysm-agent

.PHONY: dev-test-client
dev-test-client: build-test-clients ## Run test client
	@echo "Starting test client..."
	./bin/test-p2p-client wss://localhost:8443/derp test-cluster us-east

# Benchmarking targets
.PHONY: bench-derp
bench-derp: ## Benchmark DERP server
	go test -bench="BenchmarkDERPServer.*" -benchmem

.PHONY: bench-k8s
bench-k8s: ## Benchmark Prysm K8s agent
	go test -bench="BenchmarkK8sAgent.*" -benchmem

.PHONY: bench-federation
bench-federation: ## Benchmark federation
	go test -bench="BenchmarkDERPFederation.*" -benchmem

# Profiling targets
.PHONY: profile-cpu
profile-cpu: ## Run CPU profiling
	go test -cpuprofile=cpu.prof -bench="BenchmarkDERPServer_MessageThroughput"
	go tool pprof cpu.prof

.PHONY: profile-mem
profile-mem: ## Run memory profiling
	go test -memprofile=mem.prof -bench="BenchmarkDERPServer_MessageThroughput"
	go tool pprof mem.prof

# Release targets
.PHONY: release
release: clean quality test build-all-platforms docker-build ## Prepare release
	@echo "Release $(VERSION) prepared"

.PHONY: changelog
changelog: ## Generate changelog
	@echo "Generating changelog..."
	git log --oneline --pretty=format:"* %s" $(shell git describe --tags --abbrev=0)..HEAD > CHANGELOG.tmp
	@echo "Changelog generated in CHANGELOG.tmp"

# Utility targets
.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f cpu.prof mem.prof
	rm -f *.tmp
	docker system prune -f --filter "label=org.opencontainers.image.title=Prysm*"

.PHONY: gen-certs
gen-certs: ## Generate test certificates
	@echo "Generating test certificates..."
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
		-subj "/C=US/ST=CA/L=San Francisco/O=Prysm/OU=Test/CN=localhost"

.PHONY: info
info: ## Show build information
	@echo "Project: $(PROJECT_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Go Version: $(shell go version)"
	@echo "Registry: $(REGISTRY)"

# Continuous Integration targets
.PHONY: ci-setup
ci-setup: dev-setup ## Set up CI environment
	@echo "CI environment ready"

.PHONY: ci-test
ci-test: quality test ## Run CI tests
	@echo "CI tests completed"

.PHONY: ci-build
ci-build: build docker-build ## Run CI build
	@echo "CI build completed"

# Installation targets
.PHONY: install
install: build ## Install binaries to $GOPATH/bin
	cp bin/derp-server $(GOPATH)/bin/
	cp bin/prysm-agent $(GOPATH)/bin/

.PHONY: uninstall
uninstall: ## Remove binaries from $GOPATH/bin
	rm -f $(GOPATH)/bin/derp-server
	rm -f $(GOPATH)/bin/prysm-agent

# Default shell
SHELL := /bin/bash
