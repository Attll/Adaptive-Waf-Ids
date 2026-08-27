create table admin_users (
    username varchar(128) primary key,
    password_hash varchar(255) not null,
    role varchar(32) not null,
    created_at timestamp with time zone not null default now()
);

create table protected_applications (
    application_id uuid primary key,
    name varchar(128) not null unique,
    upstream_url varchar(1024) not null,
    enabled boolean not null default true,
    created_at timestamp with time zone not null default now()
);

create table policy_versions (
    policy_id uuid primary key,
    application_id uuid not null references protected_applications(application_id),
    version integer not null,
    block_risk_threshold double precision not null,
    rate_limit_short_window bigint not null,
    active boolean not null default false,
    created_at timestamp with time zone not null default now(),
    unique(application_id, version)
);

create unique index policy_versions_active_application_idx on policy_versions(application_id) where active;

create table blocked_entities (
    source_ip varchar(128) primary key,
    reason varchar(512) not null,
    blocked_by varchar(128) not null,
    expires_at timestamp with time zone not null,
    active boolean not null default true,
    updated_at timestamp with time zone not null default now()
);

create table model_versions (
    model_version_id uuid primary key,
    model_name varchar(128) not null,
    artifact_version varchar(256) not null,
    status varchar(32) not null,
    metrics_json text not null default '{}',
    created_at timestamp with time zone not null default now(),
    unique(model_name, artifact_version)
);

create table model_assignments (
    application_id uuid primary key references protected_applications(application_id),
    model_version_id uuid not null references model_versions(model_version_id),
    assigned_by varchar(128) not null,
    assigned_at timestamp with time zone not null default now()
);

create table admin_feedback (
    feedback_id uuid primary key,
    event_id varchar(64),
    verdict varchar(64) not null,
    notes varchar(4096),
    submitted_by varchar(128) not null,
    submitted_at timestamp with time zone not null default now()
);

create table audit_log (
    audit_id uuid primary key,
    administrator varchar(128) not null,
    occurred_at timestamp with time zone not null default now(),
    entity_type varchar(64) not null,
    entity_id varchar(256) not null,
    action varchar(64) not null,
    old_value_json text,
    new_value_json text not null
);

insert into protected_applications(application_id, name, upstream_url, enabled)
values ('00000000-0000-0000-0000-000000000001', 'demo-backend', 'http://127.0.0.1:8081', true)
on conflict (name) do nothing;

insert into policy_versions(policy_id, application_id, version, block_risk_threshold, rate_limit_short_window, active)
values ('00000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-000000000001', 1, 0.81, 40, true)
on conflict (policy_id) do nothing;
