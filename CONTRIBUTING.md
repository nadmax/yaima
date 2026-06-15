# Contributing

Thank you for taking the time to contribute! This document covers everything you need to know to go from a fresh clone to an accepted pull request.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Project Structure](#project-structure)
- [Coding Conventions](#coding-conventions)
- [Running Tests](#running-tests)
- [Submitting Changes](#submitting-changes)

## Getting Started

Local setup is covered in the [README Quick Start](https://github.com/nadmax/yaima/blob/master/README.md#quick-start). Follow those instructions to get the project building and the database running before working on anything else.

## Development Workflow

All common tasks are wrapped in `make` targets. Run `make help` at any time to see the full list with descriptions.

### Application

| Target | What it does |
|---|---|
| `make dev` | Run the app locally with `cargo run` |
| `make build` | Compile a release binary (`--release --locked`) |
| `make test` | Run the full test suite (unit + integration) |
| `make lint` | Run `cargo clippy` — all warnings and pedantic lints are errors |
| `make fmt` | Format code |

### Database & Migrations

| Target | What it does |
|---|---|
| `make docker-up` | Start all services |
| `make docker-down` | Stop all services |
| `make migrate` | Apply all pending migrations |
| `make migrate-revert` | Revert the last applied migration |
| `make migrate-add` | Prompt for a name and create a new reversible migration file |
| `make migrate-fresh` | Drop the database, recreate it, and replay all migrations from scratch |

### SQLx Offline Cache

The project uses `sqlx` with compile-time query checking. The `.sqlx` query cache must be kept in sync whenever you add or change a SQL query.

| Target | What it does |
|---|---|
| `make prepare` | Regenerate the `.sqlx` cache from current queries |
| `make prepare-check` | Verify the cache matches current queries (runs in CI) |

Always run `make prepare` after touching a SQL query and commit the resulting `.sqlx` changes alongside your code. CI runs `make prepare-check` and will fail if the cache is stale.

### Prek

The repository uses [`prek`](https://github.com/j178/prek) to manage Git hooks declared in `prek.toml`. The hooks run formatting and linting checks automatically before each commit, so CI should never catch something your local environment didn't.

| Target | What it does |
|---|---|
| `make prek-install` | Install the Git hooks **(run this once after cloning)** |
| `make prek-run` | Run all hooks manually against the working tree |
| `make prek-list` | List every configured hook and its status |
| `make prek-validate` | Validate `prek.toml` for syntax errors |
| `make prek-update` | Auto-update hooks to their latest versions |
| `make prek-cache-clean` | Clear the prek hook cache |

After cloning, run `make prek-install` before making any changes so the pre-commit hooks are active.

## Project Structure

```sh
src/
├── main.rs          # Binary entry point; wires up the router and starts the server
├── lib.rs           # Crate root; re-exports the public surface used by integration tests
├── config.rs        # Typed configuration loaded from environment variables
├── state.rs         # Shared application state (database pool, config, etc.) passed via Axum extensions
├── middleware.rs     # Tower middleware layers (auth extraction, request tracing, …)
├── models.rs        # Domain types and their database mappings
├── errors.rs        # Crate-wide error type; see Coding Conventions below
├── routes/
│   ├── mod.rs       # Router assembly — combines all sub-routers into one
│   ├── auth.rs      # Authentication endpoints (login, refresh, logout)
│   ├── users.rs     # User-facing endpoints
│   └── admin.rs     # Admin-only endpoints
└── services/
    ├── mod.rs        # Re-exports all services
    ├── auth.rs       # Authentication business logic
    ├── token.rs      # JWT creation and validation
    ├── user.rs       # User management business logic
    └── admin.rs      # Admin business logic

tests/
├── common/mod.rs    # Shared test helpers (app fixture, database seeding, HTTP client)
├── errors.rs        # Tests for error type behaviour and HTTP mapping
├── middleware.rs     # Tests for middleware layers in isolation
├── models.rs        # Tests for model conversions and validation
├── routes/          # Integration tests — mirror of src/routes/
└── services/        # Unit tests for service layer — mirror of src/services/
```

The `tests/` tree deliberately mirrors `src/`. When you add a new module or change existing behaviour, put the corresponding test file in the matching location under `tests/`.

## Coding Conventions

### Idiomatic Rust

These aren't hard rules to memorise before your first commit — they're pointers to help your code fit the existing style. Reviewers will flag anything that needs adjusting and are happy to explain the reasoning.

A few patterns we lean on throughout the codebase:

- **Borrowing over cloning** — prefer `&T`, `&str`, `&[T]` where possible; clone when you genuinely need ownership.
- **`?` for error propagation** — keeps call sites readable; explicit `match` chains are fine when you need to handle branches differently.
- **Iterators over manual loops** — often clearer, but don't force it if a `for` loop reads better.
- **No `unwrap()`/`expect()` outside tests** — propagate errors up to the handler layer instead.
- **No `panic!` in production paths** — if a branch truly can't fail, leave a `// Invariant:` comment explaining why.

If you're unsure about any of these, just open the PR — it's easier to iterate on real code than to get everything right upfront.

### Error Handling

All error types are defined in `src/errors.rs`. The pattern used throughout this project is:

- **`thiserror`** for structured, typed errors with `#[derive(thiserror::Error)]`.
- Each variant maps to an HTTP status code so that route handlers can return `Result<_, AppError>` directly without any extra conversion logic.
- When adding a new error condition, add a variant to the appropriate error enum in `errors.rs` rather than introducing a new ad-hoc type.
- Never swallow errors silently. If a branch genuinely cannot fail, document why with a `// SAFETY:` or `// Invariant:` comment.

### Documentation

Public items (types, functions, trait impls) must have `///` doc comments explaining what they do and any invariants the caller must uphold.

## Running Tests
```sh
make test
```

Integration tests under `tests/` spin up a real application instance against a test database. Before running them, make sure the database container is up and migrations are applied:

```sh
make docker-db       # start the database container
make migrate         # apply any pending migrations
make test            # now run the full suite
```

If your schema is out of date or you want a clean slate, use `make migrate-fresh` to drop and recreate the database before running tests.

Test names follow the pattern `<subject>_should_<expected_outcome>_when_<condition>` — for example, `login_should_return_401_when_password_is_wrong`. Aim for one logical assertion per test.

## Submitting Changes

### Branching Strategy

Branch off `master` for all changes:

```sh
git checkout -b <type>/<short-description>
```

Common branch prefixes:

| Prefix | Use for |
|---|---|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `chore/` | Tooling, dependencies, CI |
| `docs/` | Documentation only |
| `refactor/` | Code restructuring without behaviour change |
| `test/` | Adding or improving tests |`

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

```sh
feat(auth): add refresh token rotation

fix(services/token): return 401 instead of 500 on expired JWT

Closes #42
```
