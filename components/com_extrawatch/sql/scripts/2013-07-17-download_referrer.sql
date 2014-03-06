ALTER TABLE  `#__extrawatch_dm_counter` ADD  `referrerId` int DEFAULT NULL;

CREATE TABLE IF NOT EXISTS `#__extrawatch_dm_referrer` (
                  `id` int(11) NOT NULL auto_increment,
                  `referrer` varchar(255),
                  PRIMARY KEY (`id`)
                ) ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=utf8;


