UPDATE IGNORE #__modules
	SET published = 1,
	position = (SELECT T.`position` from (SELECT * FROM #__modules where position != '' and client_id = 0 order by published desc, id DESC, ordering desc limit 1) T ),
	showtitle = 0,
	params = '{"moduleclass_sfx":"","module_tag":"div","bootstrap_size":"0","header_tag":"h3","header_class":"","style":"0"}' 
	WHERE module = 'mod_extrawatch_agent' and 
	(published = 0 or position = '');

INSERT IGNORE into #__modules_menu (moduleid, menuid)values (
  (select id from #__modules where module = 'mod_extrawatch_agent' limit 1), 0
);


