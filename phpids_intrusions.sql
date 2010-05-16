CREATE TABLE IF NOT EXISTS `phpids_intrusions` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(128) NOT NULL,
  `value` text NOT NULL,
  `page` varchar(255) NOT NULL,
  `userid` int(11) unsigned NOT NULL,
  `session` varchar(32) NOT NULL,
  `ip` varchar(15) NOT NULL,
  `reaction` tinyint(3) unsigned NOT NULL COMMENT '0 = log; 1 = mail; 2 = warn; 3 = kill;',
  `impact` int(11) unsigned NOT NULL,
  `created` datetime NOT NULL,
  `tags` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
)
