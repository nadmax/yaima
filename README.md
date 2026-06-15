<h1 align="center">YAIMA</h1>
<p align="center">
    <strong>Yet Another Identity Management API</strong><br/>
    <em>Secure • Role-based • Written in Rust</em>
</p>

<p align="center">
    <a href="https://github.com/nadmax/yaima/actions">
        <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/nadmax/yaima/ci.yaml?label=CI&logo=github"/>
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img alt="License" src="https://img.shields.io/github/license/nadmax/yaima"/>
    </a>
</p>

## Features

* Built with Axum and Tokio for high-performance async workloads
* Role-based authorization (`Guest`, `User`, `Admin`)
* Account deactivation with refresh token revocation
* Admin role assignment and user management endpoints
* OpenAPI specification generation and Swagger UI
* PostgreSQL persistence powered by SQLx
* Structured error responses with stable error codes

## Prerequisites

Ensure the following tools are installed:

* Rust **1.95** or newer
* Make
* Docker
* PostgreSQL 18+
* `sqlx-cli`
* `prek`

Install `sqlx-cli`:

```sh
cargo install sqlx-cli --no-default-features --features postgres
```

Install `prek`:

```sh
cargo install prek
```

## Quick Start

1. Clone the repository

```sh
git clone https://github.com/nadmax/yaima.git
cd yaima
```

2. Install Git hooks

```sh
make prek-install
```

3. Configure the environment

```sh
cp .env.example .env
```

Minimal configuration:

```sh
DATABASE_URL=postgres://...
JWT_SECRET=your-secret-at-least-32-characters
```

4. Start dependencies
Start Postgres and Redis containers:

```sh
make docker-up
```

5. Run database migrations

```sh
make migrate
```

6. Prepare SQLx offline metadata

```sh
make prepare
```

7. Start the API

```sh
make dev
```

Docs will be available at [http://localhost:8080/apidocs](http://localhost:8080/apidocs)

## License

This project is licensed under the **MIT License**.

See the [LICENSE](https://github.com/nadmax/yaima/blob/master/LICENSE) file for details.
