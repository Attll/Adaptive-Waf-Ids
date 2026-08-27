alter table admin_feedback add column if not exists correct_attack_type varchar(128);

create table training_runs (
    training_run_id uuid primary key,
    external_run_id varchar(128) not null unique,
    model_name varchar(128) not null,
    dataset_version varchar(256) not null,
    status varchar(32) not null,
    shadow_mode boolean not null default true,
    artifact_uri varchar(1024),
    metrics_json text not null default '{}',
    drift_json text not null default '{}',
    created_by varchar(128) not null,
    started_at timestamp with time zone not null default now(),
    completed_at timestamp with time zone
);

create table model_metrics (
    model_metric_id uuid primary key,
    model_version_id uuid not null references model_versions(model_version_id),
    metric_name varchar(128) not null,
    metric_value double precision not null,
    split_name varchar(64) not null default 'validation',
    created_at timestamp with time zone not null default now()
);
