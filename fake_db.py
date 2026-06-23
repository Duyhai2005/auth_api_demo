from schemas import user_schema, token_schema

fake_users_db: dict[str, user_schema.UserInDB] = {}

fake_token_db: dict[str, token_schema.RefreshTokenInDB] = {}