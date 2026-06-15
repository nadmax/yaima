CREATE TYPE oauth_provider AS ENUM ('google', 'github');

ALTER TABLE users
    RENAME COLUMN username TO display_name;
ALTER TABLE users
    DROP COLUMN password_hash;

CREATE TABLE local_credentials (
    user_id       UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE oauth_credentials (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider          oauth_provider NOT NULL,
    provider_user_id  TEXT NOT NULL,
    access_token_enc  TEXT,
    refresh_token_enc TEXT,
    expires_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_user_id)
);
