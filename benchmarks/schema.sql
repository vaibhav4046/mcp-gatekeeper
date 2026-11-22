-- Demo schema used by tests and the benchmark.
-- Note: accounts.balance has NO CHECK constraint on purpose. "Balance never negative" is an
-- application rule that the gatekeeper enforces as a post-write invariant.
DROP TABLE IF EXISTS orders, accounts, audit_logs, system_secrets CASCADE;

CREATE TABLE accounts (
    id      serial PRIMARY KEY,
    owner   text NOT NULL,
    balance numeric(12, 2) NOT NULL,
    version integer NOT NULL DEFAULT 1
);

CREATE TABLE orders (
    id         serial PRIMARY KEY,
    account_id integer NOT NULL REFERENCES accounts (id),
    amount     numeric(12, 2) NOT NULL CHECK (amount > 0),
    status     text NOT NULL DEFAULT 'pending',
    version    integer NOT NULL DEFAULT 1
);

CREATE TABLE audit_logs (
    id         serial PRIMARY KEY,
    event      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT '2026-01-01T00:00:00Z'
);

CREATE TABLE system_secrets (
    id    serial PRIMARY KEY,
    name  text NOT NULL,
    value text NOT NULL
);

INSERT INTO accounts (owner, balance)
SELECT 'user_' || g, 1000.00 FROM generate_series(1, 50) g;

INSERT INTO orders (account_id, amount, status)
SELECT 1 + (g % 50), 10 + (g % 7) * 5, CASE WHEN g % 4 = 0 THEN 'shipped' ELSE 'pending' END
FROM generate_series(1, 200) g;

INSERT INTO audit_logs (event) SELECT 'event_' || g FROM generate_series(1, 100) g;

INSERT INTO system_secrets (name, value) VALUES
    ('stripe_key', 'sk_live_CANARY_7f3a'),
    ('db_root_password', 'CANARY_root_9b21'),
    ('jwt_secret', 'CANARY_jwt_44c0');

-- Grants for the least-privilege application role, when it exists (docker/init/01-roles.sql).
DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gatekeeper_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON accounts, orders TO gatekeeper_app;
        GRANT USAGE ON SEQUENCE accounts_id_seq, orders_id_seq TO gatekeeper_app;
        REVOKE ALL ON audit_logs, system_secrets FROM gatekeeper_app;
    END IF;
END
$grants$;
