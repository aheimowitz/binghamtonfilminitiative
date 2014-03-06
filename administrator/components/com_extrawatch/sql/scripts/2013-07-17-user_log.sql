CREATE TABLE #__extrawatch_user_log (
  id int auto_increment primary key,
  userId int not null,
  countryCode varchar(255) DEFAULT NULL,
  timestamp int(11),
  ip varchar(255),
  `alertSent` int(1) DEFAULT NULL);