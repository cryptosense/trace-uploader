.PHONY: help
help:  # from https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

sources=cs_upload.py tests

.PHONY: check-no-dependencies
check-no-dependencies:  ## Check that there are only dev dependencies
	bash ./tests/check_no_dependencies.sh

.PHONY: check-lint
check-lint:  ## Lint the code
	mypy ${sources}
	flake8 ${sources}

.PHONY: check-format
check-format:  ## Check formatting
	isort --check --diff ${sources}
	black --check --diff ${sources}

.PHONY: check-test
check-test:  ## Run unit tests
	pytest --exitfirst

.PHONY: check
check: check-format check-lint check-test check-no-dependencies  ## Run all checks

.PHONY: format
format:  ## Format all files
	isort ${sources}
	black ${sources}

.PHONY: clean
clean:  ## Delete all build products etc.
	rm -rf **/__pycache__
	rm -rf .pytest_cache
	rm -rf .mypy_cache
