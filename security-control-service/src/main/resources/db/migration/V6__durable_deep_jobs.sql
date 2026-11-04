create table deep_analysis_jobs (
    job_id uuid primary key,
    request_id uuid not null,
    state varchar(16) not null check (state in ('PENDING','RUNNING','COMPLETED','FAILED','EXPIRED')),
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    updated_at timestamptz not null default now(),
    lease_until timestamptz,
    lease_owner uuid,
    attempts integer not null default 0,
    model_version varchar(256) not null,
    outcome jsonb,
    reported boolean not null default false
);
create index deep_jobs_pending_idx on deep_analysis_jobs(state, expires_at);
create index deep_jobs_report_idx on deep_analysis_jobs(reported, updated_at) where outcome is not null;
