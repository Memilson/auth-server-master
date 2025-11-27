CREATE TABLE IF NOT EXISTS oauth_client_details (
  client_id TEXT PRIMARY KEY,
  resource_ids TEXT,
  client_secret TEXT,
  scope TEXT,
  authorized_grant_types TEXT,
  web_server_redirect_uri TEXT,
  authorities TEXT,
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information TEXT,
  autoapprove TEXT
);

CREATE TABLE IF NOT EXISTS oauth_access_token (
  token_id TEXT,
  token BLOB,
  authentication_id TEXT PRIMARY KEY,
  user_name TEXT,
  client_id TEXT,
  authentication BLOB,
  refresh_token TEXT
);

CREATE TABLE IF NOT EXISTS oauth_refresh_token (
  token_id TEXT,
  token BLOB,
  authentication BLOB
);

CREATE TABLE IF NOT EXISTS oauth_client_token (
  token_id TEXT,
  token BLOB,
  authentication_id TEXT,
  user_name TEXT,
  client_id TEXT
);

CREATE TABLE IF NOT EXISTS oauth_code (
  code TEXT,
  authentication BLOB
);

CREATE TABLE IF NOT EXISTS user_auth (
  login TEXT PRIMARY KEY,
  email TEXT UNIQUE,
  status TEXT,
  password TEXT NOT NULL,
  roles TEXT,
  tenant TEXT,
  active INTEGER DEFAULT 1,
  date TEXT,
  pass_date TEXT,
  extra TEXT
);
