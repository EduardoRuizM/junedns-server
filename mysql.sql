CREATE TABLE IF NOT EXISTS `domains` (
  `id` int(11) unsigned NOT NULL auto_increment,
  `name` varchar(100) NOT NULL,
  `nopunycode` varchar(63) NOT NULL,
  `created` date,
  `zsk_pri` text,
  `zsk_pub` text,
  `ksk_pri` text,
  `ksk_pub` text,
  `dkim` text,
  UNIQUE KEY `name` (`name`),
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `records` (
  `id` int(11) unsigned NOT NULL auto_increment,
  `domain_id` int(11) unsigned NOT NULL,
  `name` varchar(255) NOT NULL,
  `type` varchar(10),
  `content` text,
  `ttl` int(11) unsigned NOT NULL DEFAULT '259200',
  `disabled` tinyint(1) DEFAULT '0',
  `no_ip` varchar(32) CHARACTER SET latin1 COLLATE latin1_bin DEFAULT NULL,
  PRIMARY KEY  (`id`),
  KEY `name` (`name`),
  KEY `type` (`type`),
  FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Zone Example
-- INSERT INTO domains SET id=1, name='mydomain.tld';
-- INSERT INTO records SET domain_id=1, name='mydomain.tld', type='SOA', content='ns1.nsdomain.tld info.nsdomain.tld 3 10380 3600 604800 3600';
-- INSERT INTO records SET domain_id=1, name='mydomain.tld', type='A', content='1.2.3.4';
-- INSERT INTO records SET domain_id=1, name='mydomain.tld', type='AAAA', content='i:want:an:ipv6:address:so:change:me';
-- INSERT INTO records SET domain_id=1, name='mydomain.tld', type='NS', content='ns1.nsdomain.tld';
-- INSERT INTO records SET domain_id=1, name='mydomain.tld', type='NS', content='ns2.nsdomain.tld';
-- INSERT INTO records SET domain_id=1, name='www.mydomain.tld', type='CNAME', content='mydomain.tld';
-- INSERT INTO records SET domain_id=1, name='mydomain.tld', type='MX', content='mail.mydomain.tld 10';
-- INSERT INTO records SET domain_id=1, name='mail.mydomain.tld', type='A', content='1.2.3.4';
-- INSERT INTO records SET domain_id=1, name='mail.mydomain.tld', type='AAAA', content='i:want:an:ipv6:address:so:change:me';
-- INSERT INTO records SET domain_id=1, name='mydomain.tld', type='TXT', content='v=spf1 mx -all';
