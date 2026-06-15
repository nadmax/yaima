.PHONY: dev build test fmt lint docker-up docker-down docker-db docker-db-reset migrate migrate-revert migrate-add migrate-fresh prepare prepare-check prek-install prek-run prek-list prek-validate prek-update prek-cache-clean help

## help: Show this help message
help:
	@printf "\n"
	@printf "  \033[1;36m██╗   ██╗ █████╗ ██╗███╗   ███╗ █████╗ \033[0m\n"
	@printf "  \033[1;36m╚██╗ ██╔╝██╔══██╗██║████╗ ████║██╔══██╗\033[0m\n"
	@printf "  \033[1;36m ╚████╔╝ ███████║██║██╔████╔██║███████║\033[0m\n"
	@printf "  \033[1;36m  ╚██╔╝  ██╔══██║██║██║╚██╔╝██║██╔══██║\033[0m\n"
	@printf "  \033[1;36m   ██║   ██║  ██║██║██║ ╚═╝ ██║██║  ██║\033[0m\n"
	@printf "  \033[1;36m   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚═╝  ╚═╝\033[0m\n"
	@printf "\n"
	@printf "  \033[1;37mUsage:\033[0m make \033[1;36m<target>\033[0m\n"
	@printf "\n"
	@printf "  \033[1;33m%-20s %s\033[0m\n" "Target" "Description"
	@printf "  \033[90m%-20s %s\033[0m\n"  "──────────────────" "───────────────────────────────────────────"
	@grep -E '^## ' Makefile | sed 's/^## //' | awk -F': ' \
		'{ printf "  \033[1;36m%-20s\033[0m \033[37m%s\033[0m\n", $$1, $$2 }'
	@printf "\n"

## dev: Run the app locally with cargo
dev:
	@cargo run

## build: Build the release binary
build:
	@cargo build --release --locked

## test: Run all tests
test:
	@cargo test

## fmt: Format code
fmt:
	@cargo fmt

## lint: Run clippy
lint:
	@cargo clippy -- -D warnings -W clippy::pedantic

## docker-up: Start all services
docker-up:
	@docker compose up -d

## docker-down: Stop all services
docker-down:
	@docker compose down

## migrate: Run all pending migrations
migrate:
	@sqlx migrate run

## migrate-revert: Revert the last applied migration
migrate-revert:
	@sqlx migrate revert

## migrate-add: Create a new reversible migration (prompts for name)
migrate-add:
	@read -p "Migration name: " name; \
	@sqlx migrate add -r $$name

## migrate-fresh: Drop the database, recreate it and run all migrations from scratch
migrate-fresh:
	@sqlx database drop
	@sqlx database create
	@sqlx migrate run

## prepare: Generate the .sqlx query cache for offline builds
prepare:
	@cargo sqlx prepare -- --tests

## prepare-check: Verify the .sqlx cache is in sync with current queries
prepare-check:
	@cargo sqlx prepare --check -- --tests

## prek-install: Install git hooks via prek
prek-install:
	@prek install
	@prek install --hook-type commit-msg

## prek-run: Run all prek hooks manually
prek-run:
	@prek run

## prek-list: List all configured prek hooks
prek-list:
	@prek list

## prek-validate: Validate the prek.toml config file
prek-validate:
	@prek validate-config prek.toml

## prek-update: Auto-update prek hooks to their latest versions
prek-update:
	@prek auto-update

## prek-cache-clean: Clean the prek hook cache
prek-cache-clean:
	@prek cache clean
