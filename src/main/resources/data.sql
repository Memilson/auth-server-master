INSERT OR IGNORE INTO oauth_client_details (
  client_id, resource_ids, client_secret, scope, authorized_grant_types,
  web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity,
  additional_information, autoapprove
) VALUES (
  'teste', NULL, '123456', 'read,write', 'password,refresh_token',
  NULL, NULL, 3600, 7200, '{}', 'true'
);

INSERT OR IGNORE INTO user_auth (
  login, email, password, roles, tenant, active, date, pass_date, extra
) VALUES (
  'admin', 'admin@example.com',
  'ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413',
  'ROLE_ADMIN', 'default', 1, datetime('now'), datetime('now'), '{}'
);
