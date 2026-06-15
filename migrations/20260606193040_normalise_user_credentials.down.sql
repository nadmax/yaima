ALTER TABLE users
    ADD COLUMN username      TEXT,
    ADD COLUMN password_hash TEXT;

UPDATE users u
SET    username      = lc.username,
       password_hash = lc.password_hash
FROM   local_credentials lc
WHERE  lc.user_id = u.id;

-- Restore NOT NULL + UNIQUE constraints now that data is in place.
-- OAuth-only accounts (no local_credentials row) will have NULL here;
-- delete them first if the schema must be strict.

-- Optional: remove OAuth-only accounts that cannot satisfy the constraints.
-- DELETE FROM users WHERE username IS NULL OR password_hash IS NULL;

ALTER TABLE users
    ALTER COLUMN username      SET NOT NULL,
    ALTER COLUMN password_hash SET NOT NULL,
    ADD CONSTRAINT users_username_key UNIQUE (username);

ALTER TABLE users
    RENAME COLUMN display_name TO username;

DROP TABLE IF EXISTS oauth_credentials;
DROP TABLE IF EXISTS local_credentials;
DROP TYPE IF EXISTS oauth_provider;
