                DROP TABLE IF EXISTS `#__extrawatch_dm_counter`;
 
                CREATE TABLE IF NOT EXISTS `#__extrawatch_dm_counter` (
                  `id` int(11) NOT NULL auto_increment,
                  `did` int(11) NOT NULL,
                  `ddate` date NOT NULL,
                  PRIMARY KEY (`id`)
                ) ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=utf8;


                DROP TABLE IF EXISTS `#__extrawatch_dm_paths`;
 
                CREATE TABLE IF NOT EXISTS `#__extrawatch_dm_paths` (
                  `did` int(11) NOT NULL auto_increment,
                  `dname` varchar(255) NOT NULL,
                  PRIMARY KEY (`did`)
                )ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=utf8;

 
                DROP TABLE IF EXISTS `#__extrawatch_dm_extension`;
 
                CREATE TABLE IF NOT EXISTS `#__extrawatch_dm_extension` (
                  `eid` int(11) NOT NULL auto_increment,
                  `extname` varchar(25) NOT NULL,
                  PRIMARY KEY (`eid`)
                )ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=utf8;


