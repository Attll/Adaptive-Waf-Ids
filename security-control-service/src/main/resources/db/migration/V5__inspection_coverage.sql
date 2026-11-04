-- Additive: older binaries ignore these columns. Historical coverage is unknown, not inferred as success.
alter table security_events add column inspection_status varchar(32);
alter table security_events add column processed_at timestamp with time zone;
