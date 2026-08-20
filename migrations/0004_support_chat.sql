CREATE TABLE IF NOT EXISTS support_messages (
  id TEXT PRIMARY KEY,
  thread_username TEXT NOT NULL,
  sender_username TEXT NOT NULL,
  sender_display_name TEXT NOT NULL,
  sender_job_title TEXT,
  sender_role TEXT NOT NULL CHECK (sender_role IN ('admin', 'user')),
  message TEXT NOT NULL,
  created_at TEXT NOT NULL,
  read_by_admin INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_support_thread_created ON support_messages(thread_username, created_at);
CREATE INDEX IF NOT EXISTS idx_support_unread ON support_messages(read_by_admin, created_at);
