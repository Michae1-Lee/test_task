CREATE TABLE sessions
(
    id VARCHAR(255) PRIMARY KEY NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    ip VARCHAR(255) NOT NULL,
    refresh_token VARCHAR NOT NULL,
    access_token VARCHAR NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);
