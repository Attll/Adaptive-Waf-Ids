create table security_events (
    id bigserial primary key,
    event_id varchar(36) not null unique,
    occurred_at timestamp with time zone not null,
    category varchar(64) not null,
    request_id varchar(64),
    source_hash varchar(64),
    method varchar(16),
    path varchar(1024),
    status_code integer not null,
    action varchar(64),
    predicted_attack varchar(128),
    risk double precision not null,
    details_json text not null
);

create index security_events_occurred_at_idx on security_events (occurred_at desc);
create index security_events_category_idx on security_events (category);
