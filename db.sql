CREATE TABLE keycloak (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    access_token TEXT,
    refresh_token TEXT,
    expires_in TIMESTAMP,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);