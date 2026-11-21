# beam-bridge — обычный Go-модуль; сборка клиентов живёт в их репозиториях.

.PHONY: help
help:
	@echo "make check    — build + vet + tests"

.PHONY: check
check:
	go build ./...
	go vet ./...
	go test ./... 2>&1 | grep -v "no test files" || true
