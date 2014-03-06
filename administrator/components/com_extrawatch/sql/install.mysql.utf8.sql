


                CREATE TABLE IF NOT EXISTS `#__extrawatch` (
                `id` int unsigned auto_increment primary key,
                `ip` varchar(255) default NULL,
                `country` varchar(2) default NULL,
                `browser` varchar(255) default NULL COLLATE utf8_general_ci,
                `referer` varchar(255) default NULL COLLATE utf8_general_ci,
                `username` varchar(255) default NULL COLLATE utf8_general_ci,
				  KEY `ip` (`ip`),
				  KEY `browser` (`browser`),
				  KEY `country` (`country`)
                );


                CREATE TABLE IF NOT EXISTS `#__extrawatch_config` (
                `id` int unsigned auto_increment primary key,
                `name` varchar(255) default NULL COLLATE utf8_general_ci,
                `value` TEXT default NULL COLLATE utf8_general_ci
				);

  			    ALTER IGNORE TABLE #__extrawatch_config ADD UNIQUE INDEX(name);

                CREATE TABLE IF NOT EXISTS `#__extrawatch_info` (
                `id` int unsigned auto_increment primary key,
                `group` int(3) default NULL COLLATE utf8_general_ci,
                `date` int(6) default NULL COLLATE utf8_general_ci,
                `name` varchar(255) default NULL COLLATE utf8_general_ci,
                `value` int unsigned default NULL COLLATE utf8_general_ci,
				  KEY `group` (`group`),
				  KEY `name` (`name`),
				  KEY `date` (`date`)
                );


                CREATE TABLE IF NOT EXISTS `#__extrawatch_ip2c` (
                `start` int(10) unsigned NOT NULL default '0',
                `end` int(10) unsigned NOT NULL default '0',
                `country` char(2) NOT NULL default '',
				  KEY `start` (`start`),
				  KEY `end` (`end`)
                );


                CREATE TABLE IF NOT EXISTS `#__extrawatch_uri` (
                `id` int unsigned auto_increment primary key,
                `fk` int unsigned default NULL,
                `timestamp` int unsigned default NULL,
                `uri` varchar(255) default NULL COLLATE utf8_general_ci,
                `title` varchar(255) default NULL COLLATE utf8_general_ci,
				  KEY `fk` (`fk`),
				  KEY `timestamp` (`timestamp`)
                );



                CREATE TABLE IF NOT EXISTS `#__extrawatch_blocked` (
                `id` int unsigned auto_increment primary key,
                `ip` varchar(255) default NULL,
                `hits` int unsigned default NULL,
                `date` int(5) default NULL,
                `reason` varchar(255) default NULL COLLATE utf8_general_ci,
				`country` char(2) DEFAULT NULL,
				`badWord` varchar(255) NOT NULL,
				  KEY `ip` (`ip`),
				  KEY `date` (`date`)
                );


                CREATE TABLE IF NOT EXISTS `#__extrawatch_goals` (
                `id` int(11) NOT NULL auto_increment primary key,
                `name` varchar(255) default NULL COLLATE utf8_general_ci,
                `username_inversed` varchar(3) DEFAULT NULL,
                `parentId` int(11) default NULL,
                `uri_condition` varchar(255) default NULL COLLATE utf8_general_ci,
                `uri_inversed` varchar(3) DEFAULT NULL,
                `get_var` varchar(255) default NULL COLLATE utf8_general_ci,
                `get_condition` varchar(255) default NULL COLLATE utf8_general_ci,
                `get_inversed` varchar(3) DEFAULT NULL,
                `post_var` varchar(255) default NULL COLLATE utf8_general_ci,
                `post_condition` varchar(255) default NULL COLLATE utf8_general_ci,
                `post_inversed` varchar(3) DEFAULT NULL,
                `title_condition` varchar(255) default NULL COLLATE utf8_general_ci,
                `title_inversed` varchar(3) DEFAULT NULL,
                `username_condition` varchar(255) default NULL COLLATE utf8_general_ci,
                `ip_condition` varchar(255) default NULL COLLATE utf8_general_ci,
                `ip_inversed` varchar(3) DEFAULT NULL,
                `came_from_condition` varchar(255) default NULL COLLATE utf8_general_ci,
                `came_from_inversed` varchar(3) DEFAULT NULL,
                `country_condition` varchar(255) default NULL COLLATE utf8_general_ci,
                `country_inversed` varchar(3) DEFAULT NULL,
                `block` varchar(255) default NULL COLLATE utf8_general_ci,
                `redirect` varchar(255) default NULL COLLATE utf8_general_ci,
                `disabled` tinyint(1) default NULL
                );



                CREATE TABLE IF NOT EXISTS `#__extrawatch_cache` (
                `id` int(11) NOT NULL auto_increment primary key,
                `key` varchar(255) default NULL COLLATE utf8_general_ci,
                `lastUpdate` int(11) default NULL,
                `cache` mediumtext COLLATE utf8_general_ci,
				KEY `key` (`key`)
                );



                CREATE TABLE IF NOT EXISTS `#__extrawatch_cc2c` (
                `id` tinyint(3) unsigned NOT NULL auto_increment primary key,
                `cc` char(2) NOT NULL,
                `country` varchar(50) NOT NULL,
				KEY `cc` (`cc`)
                );



                INSERT IGNORE INTO `#__extrawatch_cc2c` (`id`, `cc`, `country`) VALUES
                (1, 'gb', 'United Kingdom'),
                (2, 'us', 'United States'),
                (3, 'bm', 'Bermuda'),
                (4, 'se', 'Sweden'),
                (5, 'it', 'Italy'),
                (6, 'ca', 'Canada'),
                (7, 'vi', 'Virgin Islands, U.S.'),
                (8, 'pr', 'Puerto Rico'),
                (9, 'bo', 'Bolivia'),
                (10, 'nl', 'Netherlands'),
                (11, 'de', 'Germany'),
                (12, 'ch', 'Switzerland'),
                (13, 'fr', 'France'),
                (14, 'il', 'Israel'),
                (15, 'es', 'Spain'),
                (16, 'cl', 'Chile'),
                (17, 'bs', 'Bahamas'),
                (18, 'ar', 'Argentina'),
                (19, 'dm', 'Dominica'),
                (20, 'be', 'Belgium'),
                (21, 'ie', 'Ireland'),
                (22, 'bz', 'Belize'),
                (23, 'br', 'Brazil'),
                (24, 'mx', 'Mexico'),
                (25, 'jp', 'Japan'),
                (26, 'in', 'India'),
                (27, 'au', 'Australia'),
                (28, 'th', 'Thailand'),
                (29, 'cn', 'China'),
                (30, 'my', 'Malaysia'),
                (31, 'pk', 'Pakistan'),
                (32, 'nz', 'New Zealand'),
                (33, 'kr', 'Republic Of Korea'),
                (34, 'hk', 'Hong Kong'),
                (35, 'sg', 'Singapore'),
                (36, 'bd', 'Bangladesh'),
                (37, 'id', 'Indonesia'),
                (38, 'ph', 'Philippines'),
                (39, 'tw', 'Taiwan'),
                (40, 'af', 'Afghanistan'),
                (41, 'vn', 'Viet Nam'),
                (42, 'pa', 'Panama'),
                (43, 'nc', 'New Caledonia'),
                (44, 'bn', 'Brunei Darussalam'),
                (45, 'gr', 'Greece'),
                (46, 'sa', 'Saudi Arabia'),
                (47, 'pl', 'Poland'),
                (48, 'me', 'Montenegro'),
                (49, 'cz', 'Czech Republic'),
                (50, 'ru', 'Russian Federation'),
                (51, 'dk', 'Denmark'),
                (52, 'zw', 'Zimbabwe'),
                (53, 'iq', 'Iraq'),
                (54, 'fi', 'Finland'),
                (55, 'ir', 'Islamic Republic Of Iran'),
                (56, 'eg', 'Egypt'),
                (57, 'ng', 'Nigeria'),
                (58, 'ae', 'United Arab Emirates'),
                (59, 'gh', 'Ghana'),
                (60, 'ga', 'Gabon'),
                (61, 'ug', 'Uganda'),
                (62, 'sd', 'Sudan'),
                (63, 'cy', 'Cyprus'),
                (64, 'no', 'Norway'),
                (65, 'at', 'Austria'),
                (66, 'ua', 'Ukraine'),
                (67, 'tj', 'Tajikistan'),
                (68, 'pt', 'Portugal'),
                (69, 'tr', 'Turkey'),
                (70, 'ge', 'Georgia'),
                (71, 'by', 'Belarus'),
                (72, 'am', 'Armenia'),
                (73, 'lb', 'Lebanon'),
                (74, 'md', 'Republic Of Moldova'),
                (75, 'bg', 'Bulgaria'),
                (76, 'mz', 'Mozambique'),
                (77, 'ao', 'Angola'),
                (78, 'ke', 'Kenya'),
                (79, 'cd', 'The Democratic Republic Of The Congo'),
                (80, 'mg', 'Madagascar'),
                (81, 'tz', 'United Republic Of Tanzania'),
                (82, 'tg', 'Togo'),
                (83, 'zm', 'Zambia'),
                (84, 'cm', 'Cameroon'),
                (85, 'om', 'Oman'),
                (86, 'lv', 'Latvia'),
                (87, 'kz', 'Kazakhstan'),
                (88, 'ee', 'Estonia'),
                (89, 'sk', 'Slovakia'),
                (90, 'ba', 'Bosnia And Herzegovina'),
                (91, 'hu', 'Hungary'),
                (92, 'kw', 'Kuwait'),
                (93, 'al', 'Albania'),
                (94, 'lt', 'Lithuania'),
                (95, 'lr', 'Liberia'),
                (96, 'sm', 'San Marino'),
                (97, 'ro', 'Romania'),
                (98, 'cs', 'Serbia And Montenegro'),
                (99, 'rs', 'Serbia'),
                (100, 'lu', 'Luxembourg'),
                (101, 'ma', 'Morocco'),
                (102, 'dz', 'Algeria'),
                (103, 'is', 'Iceland'),
                (104, 'cr', 'Costa Rica'),
                (105, 'mk', 'The Former Yugoslav Republic Of Macedonia'),
                (106, 'mt', 'Malta'),
                (107, 'gm', 'Gambia'),
                (108, 'sz', 'Swaziland'),
                (109, 'za', 'South Africa'),
                (110, 'mw', 'Malawi'),
                (111, 'fk', 'Falkland Islands (Malvinas)'),
                (112, 'bh', 'Bahrain'),
                (113, 'uz', 'Uzbekistan'),
                (114, 'az', 'Azerbaijan'),
                (115, 'mc', 'Monaco'),
                (116, 'ht', 'Haiti'),
                (117, 'gu', 'Guam'),
                (118, 'fm', 'Federated States Of Micronesia'),
                (119, 'co', 'Colombia'),
                (120, 'ec', 'Ecuador'),
                (121, 'ky', 'Cayman Islands'),
                (122, 'pe', 'Peru'),
                (123, 'hn', 'Honduras'),
                (124, 'sl', 'Sierra Leone'),
                (125, 'ml', 'Mali'),
                (126, 'lc', 'Saint Lucia'),
                (127, 'vg', 'Virgin Islands, British'),
                (128, 'ni', 'Nicaragua'),
                (129, 'do', 'Dominican Republic'),
                (130, 'an', 'Netherlands Antilles'),
                (131, 'gt', 'Guatemala'),
                (132, 'tt', 'Trinidad And Tobago'),
                (133, 'bv', 'Bouvet Island'),
                (134, 've', 'Venezuela'),
                (135, 'ws', 'Samoa'),
                (136, 'mh', 'Marshall Islands'),
                (137, 'mp', 'Northern Mariana Islands'),
                (138, 'pw', 'Palau'),
                (139, 'bb', 'Barbados'),
                (140, 'gd', 'Grenada'),
                (141, 'vc', 'Saint Vincent And The Grenadines'),
                (142, 'sv', 'El Salvador'),
                (143, 'jm', 'Jamaica'),
                (144, 'cu', 'Cuba'),
                (145, 'tc', 'Turks And Caicos Islands'),
                (146, 'cg', 'Congo'),
                (147, 'py', 'Paraguay'),
                (148, 'rw', 'Rwanda'),
                (149, 'sr', 'Suriname'),
                (150, 'gy', 'Guyana'),
                (151, 'pg', 'Papua New Guinea'),
                (152, 'kn', 'Saint Kitts And Nevis'),
                (153, 'ag', 'Antigua And Barbuda'),
                (154, 'gi', 'Gibraltar'),
                (155, 'aw', 'Aruba'),
                (156, 'uy', 'Uruguay'),
                (157, 'jo', 'Jordan'),
                (158, 'sy', 'Syrian Arab Republic'),
                (159, 'um', 'United States Minor Outlying Islands'),
                (160, 'si', 'Slovenia'),
                (161, 'mu', 'Mauritius'),
                (162, 'bf', 'Burkina Faso'),
                (163, 'ne', 'Niger'),
                (164, 'je', 'Jersey'),
                (165, 'kg', 'Kyrgyzstan'),
                (166, 'tm', 'Turkmenistan'),
                (167, 'hr', 'Croatia'),
                (168, 'im', 'Isle Of Man'),
                (169, 'gn', 'Guinea'),
                (170, 'mm', 'Myanmar'),
                (171, 'bj', 'Benin'),
                (172, 'cf', 'Central African Republic'),
                (173, 'et', 'Ethiopia'),
                (174, 'np', 'Nepal'),
                (175, 'bt', 'Bhutan'),
                (176, 'qa', 'Qatar'),
                (177, 'na', 'Namibia'),
                (178, 'bw', 'Botswana'),
                (179, 'td', 'Chad'),
                (180, 'ax', 'Aland Islands'),
                (181, 'li', 'Liechtenstein'),
                (182, 're', 'Reunion'),
                (183, 'ci', 'Cote D''Ivoire'),
                (184, 'fo', 'Faroe Islands'),
                (185, 'so', 'Somalia'),
                (186, 'ps', 'Palestinian Territory, Occupied'),
                (187, 'gq', 'Equatorial Guinea'),
                (188, 'sn', 'Senegal'),
                (189, 'tn', 'Tunisia'),
                (190, 'ye', 'Yemen'),
                (191, 'km', 'Comoros'),
                (192, 'bi', 'Burundi'),
                (193, 'ls', 'Lesotho'),
                (194, 'mr', 'Mauritania'),
                (195, 'nr', 'Nauru'),
                (196, 'ly', 'Libyan Arab Jamahiriya'),
                (197, 'sc', 'Seychelles'),
                (198, 'la', 'Lao People''S Democratic Republic'),
                (199, 'lk', 'Sri Lanka'),
                (200, 'mq', 'Martinique'),
                (201, 'gp', 'Guadeloupe'),
                (202, 'va', 'Holy See (Vatican City State)'),
                (203, 'yt', 'Mayotte'),
                (204, 'aq', 'Antarctica'),
                (205, 'ad', 'Andorra'),
                (206, 'mo', 'Macao'),
                (207, 'cv', 'Cape Verde'),
                (208, 'gl', 'Greenland'),
                (209, 'gw', 'Guinea-Bissau'),
                (210, 'er', 'Eritrea'),
                (211, 'vu', 'Vanuatu'),
                (212, 'fj', 'Fiji'),
                (213, 'kh', 'Cambodia'),
                (214, 'mn', 'Mongolia'),
                (215, 'mv', 'Maldives'),
                (216, 'wf', 'Wallis And Futuna'),
                (217, 'pf', 'French Polynesia'),
                (218, 'dj', 'Djibouti'),
                (219, 'st', 'Sao Tome And Principe'),
                (220, 'ms', 'Montserrat'),
                (221, 'tf', 'French Southern Territories'),
                (222, 'gf', 'French Guiana'),
                (223, 'gs', 'South Georgia And The South Sandwich Islands'),
                (224, 'sb', 'Solomon Islands'),
                (225, 'tv', 'Tuvalu'),
                (226, 'ki', 'Kiribati'),
                (227, 'to', 'Tonga'),
                (228, 'io', 'British Indian Ocean Territory'),
                (229, 'nu', 'Niue'),
                (230, 'ck', 'Cook Islands'),
                (231, 'as', 'American Samoa'),
                (232, 'tl', 'Timor-Leste'),
                (233, 'tk', 'Tokelau'),
                (234, 'nf', 'Norfolk Island'),
                (235, 'ai', 'Anguilla'),
                (236, 'eu', 'European Union');



                CREATE TABLE IF NOT EXISTS `#__extrawatch_uri2title` (
                `id` int(11) NOT NULL auto_increment primary key,
                `uri` varchar(255) default NULL COLLATE utf8_general_ci,
                `title` varchar(255) default NULL COLLATE utf8_general_ci,
                `count` int(11) default 0,
                `timestamp` int(11) default NULL,
				KEY `uri` (`uri`)
                );

                ALTER IGNORE TABLE #__extrawatch_uri2title ADD UNIQUE INDEX(uri);

                CREATE TABLE IF NOT EXISTS `#__extrawatch_internal` (
                `id` int(11) NOT NULL auto_increment primary key,
                `from` varchar(255) default NULL COLLATE utf8_general_ci,
                `to` varchar(255) default NULL COLLATE utf8_general_ci,
                `timestamp` int(11) default NULL,
				KEY `from` (`from`),
				KEY `to` (`to`)
                );



                CREATE TABLE IF NOT EXISTS `#__extrawatch_history` (
                `id` int unsigned auto_increment primary key,
                `ip` varchar(255) default NULL,
                `country` varchar(2) default NULL,
                `browser` varchar(255) default NULL COLLATE utf8_general_ci,
                `referer` varchar(255) default NULL COLLATE utf8_general_ci,
                `username` varchar(255) default NULL COLLATE utf8_general_ci,
				  KEY `ip` (`ip`),
				  KEY `browser` (`browser`),
				  KEY `country` (`country`)
                );




                CREATE TABLE IF NOT EXISTS `#__extrawatch_uri_history` (
                `id` int unsigned auto_increment primary key,
                `fk` int unsigned default NULL,
                `timestamp` int unsigned default NULL,
                `uri` varchar(255) default NULL COLLATE utf8_general_ci,
                `title` varchar(255) default NULL COLLATE utf8_general_ci,
				  KEY `fk` (`fk`),
				  KEY `timestamp` (`timestamp`)
                );



				CREATE TABLE IF NOT EXISTS `#__extrawatch_flow` (
				`id` int(11) NOT NULL auto_increment primary key,
				`from` int(11) default NULL,
				`to` int(11) default NULL,
				`count` int(11) default NULL,
                KEY `from` (`from`),
                KEY `to` (`to`)
				);


				CREATE TABLE IF NOT EXISTS `#__extrawatch_uri_post` (
				`id` int(11) NOT NULL auto_increment,
				`uriid` int(11) NOT NULL,
				`key` varchar(255) NOT NULL,
				`value` varchar(255) NOT NULL,
				`type` int(11) NOT NULL,
				PRIMARY KEY  (`id`),
				KEY `uriid` (`uriid`),
				KEY `type` (`type`)
				);

				CREATE TABLE IF NOT EXISTS `#__extrawatch_keyphrase` (
				`id` int(11) NOT NULL AUTO_INCREMENT,
				`name` varchar(255) DEFAULT NULL,
				PRIMARY KEY (`id`)
				);

				CREATE TABLE IF NOT EXISTS `#__extrawatch_uri2keyphrase` (
				`id` int(11) NOT NULL AUTO_INCREMENT,
				`uri2titleId` int(11) NOT NULL,
				`keyphraseId` int(11) NOT NULL,
				PRIMARY KEY (`id`)
				);

				CREATE TABLE IF NOT EXISTS `#__extrawatch_heatmap` (
				  `id` int(11) NOT NULL auto_increment,
				  `uri2titleId` int(11) NOT NULL,
				  `x` smallint(5) unsigned NOT NULL,
				  `y` smallint(7) unsigned NOT NULL,
				  `w` smallint(5) unsigned NOT NULL,
				  `h` smallint(5) NOT NULL,
				  `ip` varchar(255) NOT NULL,
				  `day` int(11) default NULL,
				  `timestamp` int(11) default NULL,
				  `xpath` varchar(1024) NOT NULL,
				  PRIMARY KEY  (`id`),
				  KEY `uri2titleId` (`uri2titleId`),
				  KEY `day` (`day`)
				);

				CREATE TABLE IF NOT EXISTS `#__extrawatch_uri2keyphrase_pos` (
				`id` int(11) NOT NULL auto_increment,
				`uri2keyphraseId` int(11) default NULL,
				`position` int(11) default NULL,
				PRIMARY KEY  (`id`)
				);



				CREATE TABLE IF NOT EXISTS `#__extrawatch_sql_scripts` (
				`id` int(11) NOT NULL auto_increment,
				`scriptname` varchar(255) default NULL,
				PRIMARY KEY  (`id`)
				);
				
				ALTER TABLE #__extrawatch_uri
				ADD FOREIGN KEY (fk)
				REFERENCES #__extrawatch(id) ON DELETE CASCADE;



