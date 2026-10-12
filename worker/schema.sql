CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,salt TEXT NOT NULL,pass_hash TEXT NOT NULL,failures INTEGER NOT NULL DEFAULT 0,locked_until INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_session_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS credentials(user_id TEXT PRIMARY KEY REFERENCES users(id),iv TEXT NOT NULL,sealed TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rate_limits(user_id TEXT NOT NULL REFERENCES users(id),minute INTEGER NOT NULL,count INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(user_id,minute));
-- Shared Workers AI budget reservation, reset by UTC day. No API keys stored.
CREATE TABLE IF NOT EXISTS ai_daily_limits(day INTEGER NOT NULL, scope TEXT NOT NULL, calls INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(day,scope));
