-- Retain the observable source address and per-request decision evidence instead of an opaque digest so the
-- security console can map attacks to origins and replay how a request travelled the detection pipeline.
alter table security_events add column if not exists source_ip varchar(64);
alter table security_events add column if not exists query varchar(2048);
alter table security_events add column if not exists mitigation varchar(64);
alter table security_events add column if not exists mode varchar(32);
alter table security_events add column if not exists user_agent varchar(512);
alter table security_events add column if not exists upstream varchar(1024);
alter table security_events add column if not exists detection_latency_ms double precision not null default 0;
alter table security_events add column if not exists upstream_latency_ms double precision not null default 0;
alter table security_events add column if not exists gateway_latency_ms double precision not null default 0;
alter table security_events add column if not exists routing_path varchar(512);
alter table security_events add column if not exists deep_model_used boolean not null default false;
alter table security_events add column if not exists triage_decision varchar(32);
alter table security_events add column if not exists confidence double precision not null default 0;

alter table security_events alter column details_json type text;
alter table security_events drop column if exists source_hash;

create index if not exists security_events_source_ip_idx on security_events (source_ip);
create index if not exists security_events_action_idx on security_events (action);
create index if not exists security_events_predicted_attack_idx on security_events (predicted_attack);
