CREATE TABLE #__extrawatch_ip2c_cache (
  id int auto_increment primary key,
  ip varchar(255) not null,
  countryCode varchar(255) not null
  );

CREATE INDEX ip_idx ON #__extrawatch_ip2c_cache (ip);
