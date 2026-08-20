ALTER TABLE app_users ADD COLUMN job_title TEXT CHECK (job_title IN ('LOG', 'OPS3', 'TEAM LEADER', 'PS'));
