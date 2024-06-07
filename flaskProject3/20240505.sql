-- MySQL dump 10.13  Distrib 5.7.26, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: hids
-- ------------------------------------------------------
-- Server version	5.7.26

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `agent`
--

DROP TABLE IF EXISTS `agent`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `agent` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `host_name` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `ip_address` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `os_version` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
  `status` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `last_seen` datetime DEFAULT NULL,
  `disk_total` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `mem_total` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `mem_use` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `cpu_use` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `py_version` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `processor_name` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `processor_architecture` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `uuid` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `agent`
--

LOCK TABLES `agent` WRITE;
/*!40000 ALTER TABLE `agent` DISABLE KEYS */;
INSERT INTO `agent` VALUES (1,'3123123123123','127.0.0.1','1','1','2024-03-28 21:22:36','123','1231','31231','3123','123','3123','312313',NULL);
/*!40000 ALTER TABLE `agent` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `asset_mapping`
--

DROP TABLE IF EXISTS `asset_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `asset_mapping` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `protocol` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `port` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `service` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `product` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `version` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `ostype` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `uuid` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `asset_mapping`
--

LOCK TABLES `asset_mapping` WRITE;
/*!40000 ALTER TABLE `asset_mapping` DISABLE KEYS */;
/*!40000 ALTER TABLE `asset_mapping` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `fileintegrityinfo`
--

DROP TABLE IF EXISTS `fileintegrityinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `fileintegrityinfo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `filename` varchar(256) DEFAULT NULL,
  `file_content_md5` varchar(256) DEFAULT NULL,
  `filename_md5` varchar(256) DEFAULT NULL,
  `ctime` varchar(256) DEFAULT NULL,
  `mtime` varchar(256) DEFAULT NULL,
  `atime` varchar(256) DEFAULT NULL,
  `host_IP` varchar(256) DEFAULT NULL,
  `host_name` varchar(256) DEFAULT NULL,
  `is_exists` varchar(256) DEFAULT NULL,
  `event_time` varchar(256) DEFAULT NULL,
  `uuid` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=184 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `fileintegrityinfo`
--

LOCK TABLES `fileintegrityinfo` WRITE;
/*!40000 ALTER TABLE `fileintegrityinfo` DISABLE KEYS */;
INSERT INTO `fileintegrityinfo` VALUES (1,'/Users/polowong/Desktop/.DS_Store','123','b0e73f72c74f8dcebcbc0c7cabc3f96c','1705318878.0285628','1705318878.0285628','1705318886.0948737','218.194.48.204','Polos-Workstation.local','1','1705319758.993375',NULL),(2,'/Users/polowong/Desktop/研究生工作','d2b2febbf8dc6a033e5ad6c351a5ed5d','caf3643fb62cee6e3b26f4ec70e34784','1703237960.6623635','1702700015.9956796','1702700016.226547','218.194.48.204','Polos-Workstation.local','1','1705319758.994272',NULL),(3,'/Users/polowong/Desktop/研究生工作','dcebcbc0c7cb0e74f8abc3f96c73f72c','caf3643fb62cee6e3b26f4ec70e34784','1703237960.6623635','1702700015.9956796','1702700016.226547','218.194.48.204','Polos-Workstation.local','1','1705311258.994272',NULL);
/*!40000 ALTER TABLE `fileintegrityinfo` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `host_info`
--

DROP TABLE IF EXISTS `host_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `host_info` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(15) DEFAULT NULL,
  `state` varchar(256) NOT NULL,
  `uuid` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `host_info` (`uuid`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `host_info`
--

LOCK TABLES `host_info` WRITE;
/*!40000 ALTER TABLE `host_info` DISABLE KEYS */;
INSERT INTO `host_info` VALUES (1,'127.0.0.1','1','abc'),(2,'127.0.0.1','1','bcd');
/*!40000 ALTER TABLE `host_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `linux_security_checks`
--

DROP TABLE IF EXISTS `linux_security_checks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `linux_security_checks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `check_name` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `details` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `adjustment_requirement` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `instruction` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `status` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `last_checked` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `uuid` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `linux_security_checks`
--

LOCK TABLES `linux_security_checks` WRITE;
/*!40000 ALTER TABLE `linux_security_checks` DISABLE KEYS */;
/*!40000 ALTER TABLE `linux_security_checks` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `monitored_files`
--

DROP TABLE IF EXISTS `monitored_files`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `monitored_files` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `agentIP` varchar(15) NOT NULL,
  `file_path` varchar(255) NOT NULL,
  `change_type` varchar(10) NOT NULL,
  `file_type` varchar(10) DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `uuid` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `monitored_files`
--

LOCK TABLES `monitored_files` WRITE;
/*!40000 ALTER TABLE `monitored_files` DISABLE KEYS */;
INSERT INTO `monitored_files` VALUES (1,'127.0.0.1','C://','created','file','2024-01-25 15:11:33',NULL),(2,'127.0.0.1','D://','deleted','file','2024-01-25 15:11:33',NULL);
/*!40000 ALTER TABLE `monitored_files` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `port_info`
--

DROP TABLE IF EXISTS `port_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `port_info` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `host_ip` varchar(15) DEFAULT NULL,
  `uuid` varchar(255) DEFAULT NULL,
  `port_number` int(11) NOT NULL,
  `port_state` varchar(256) NOT NULL,
  `port_name` varchar(256) NOT NULL,
  `product` varchar(256) DEFAULT NULL,
  `version` varchar(256) DEFAULT NULL,
  `extrainfo` varchar(256) DEFAULT NULL,
  `script_http_title` text,
  `script_http_server_header` text,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `uuid` (`uuid`) USING BTREE,
  CONSTRAINT `fk_port_info_host_uuid` FOREIGN KEY (`uuid`) REFERENCES `host_info` (`uuid`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `port_info`
--

LOCK TABLES `port_info` WRITE;
/*!40000 ALTER TABLE `port_info` DISABLE KEYS */;
INSERT INTO `port_info` VALUES (1,'127.0.0.1','abc',1,'1','1','1','1','1','1','1'),(2,'127.0.0.1','bcd',1,'1','1','1','1','12','323','123');
/*!40000 ALTER TABLE `port_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `process_info`
--

DROP TABLE IF EXISTS `process_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `process_info` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `agentIP` varchar(15) NOT NULL,
  `scanTime` datetime NOT NULL,
  `pid` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `userName` varchar(255) NOT NULL,
  `exe` varchar(255) DEFAULT NULL,
  `cmdline` text NOT NULL,
  `cpuPercent` double NOT NULL,
  `memoryPercent` double NOT NULL,
  `createTime` datetime NOT NULL,
  `highRisk` varchar(255) NOT NULL,
  `uuid` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `process_info`
--

LOCK TABLES `process_info` WRITE;
/*!40000 ALTER TABLE `process_info` DISABLE KEYS */;
/*!40000 ALTER TABLE `process_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_honeypot`
--

DROP TABLE IF EXISTS `tb_honeypot`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_honeypot` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键id',
  `agent_ip` varchar(255) DEFAULT NULL COMMENT 'Agent的ip地址',
  `atk_ip` varchar(255) DEFAULT NULL COMMENT '攻击者的ip地址',
  `atk_time` datetime DEFAULT NULL COMMENT '攻击时间',
  `uuid` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 ROW_FORMAT=COMPACT;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_honeypot`
--

LOCK TABLES `tb_honeypot` WRITE;
/*!40000 ALTER TABLE `tb_honeypot` DISABLE KEYS */;
INSERT INTO `tb_honeypot` VALUES (3,'127.0.0.1','123123','2024-04-06 21:16:13','123');
/*!40000 ALTER TABLE `tb_honeypot` ENABLE KEYS */;
UNLOCK TABLES;


--
-- Table structure for table `memory_shell`
--

DROP TABLE IF EXISTS `memory_shell`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `memory_shell` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `shell_data` varchar(520) DEFAULT NULL,
  `shell_poc` varchar(520) DEFAULT NULL,
  `is_shell` varchar(10) DEFAULT NULL,
  `detect_time` datetime DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 ROW_FORMAT=COMPACT;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vul_detection_result`
--

DROP TABLE IF EXISTS `vul_detection_result`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `vul_detection_result` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scanTime` datetime NOT NULL,
  `scanType` varchar(255) NOT NULL,
  `ip` varchar(15) NOT NULL,
  `port` varchar(255) NOT NULL,
  `uuid` varchar(255) NOT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `uuid` (`uuid`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vul_detection_result`
--

LOCK TABLES `vul_detection_result` WRITE;
/*!40000 ALTER TABLE `vul_detection_result` DISABLE KEYS */;
INSERT INTO `vul_detection_result` VALUES (1,'2024-03-23 11:34:32','1','127.0.0.1','8888,80,81','aaa'),(2,'2024-03-23 11:42:31','1','127.0.0.2','80,22','bbb');
/*!40000 ALTER TABLE `vul_detection_result` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vul_detection_result_bug_exp`
--

DROP TABLE IF EXISTS `vul_detection_result_bug_exp`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `vul_detection_result_bug_exp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scanTime` datetime NOT NULL,
  `ip` varchar(15) NOT NULL,
  `bug_exp` varchar(255) NOT NULL,
  `uuid` varchar(255) NOT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `uuid_foreign0` (`uuid`) USING BTREE,
  CONSTRAINT `uuid_foreign0` FOREIGN KEY (`uuid`) REFERENCES `vul_detection_result` (`uuid`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vul_detection_result_bug_exp`
--

LOCK TABLES `vul_detection_result_bug_exp` WRITE;
/*!40000 ALTER TABLE `vul_detection_result_bug_exp` DISABLE KEYS */;
INSERT INTO `vul_detection_result_bug_exp` VALUES (1,'2024-03-23 11:35:44','127.0.0.1','CVE-2222-2222','aaa'),(4,'2024-03-23 11:42:14','127.0.0.2','1111','aaa');
/*!40000 ALTER TABLE `vul_detection_result_bug_exp` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vul_detection_result_bug_poc`
--

DROP TABLE IF EXISTS `vul_detection_result_bug_poc`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `vul_detection_result_bug_poc` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scanTime` datetime NOT NULL,
  `ip` varchar(15) NOT NULL,
  `url` text NOT NULL,
  `bug_poc` varchar(255) NOT NULL,
  `uuid` varchar(255) NOT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `uuid_foreign1` (`uuid`) USING BTREE,
  CONSTRAINT `uuid_foreign1` FOREIGN KEY (`uuid`) REFERENCES `vul_detection_result` (`uuid`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vul_detection_result_bug_poc`
--

LOCK TABLES `vul_detection_result_bug_poc` WRITE;
/*!40000 ALTER TABLE `vul_detection_result_bug_poc` DISABLE KEYS */;
INSERT INTO `vul_detection_result_bug_poc` VALUES (1,'2024-03-23 11:36:15','127.0.0.1','http://127.0.0.1/abc','poc-yaml-drupal-cve-2014-3704-sqli','bbb');
/*!40000 ALTER TABLE `vul_detection_result_bug_poc` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vul_detection_result_finger`
--

DROP TABLE IF EXISTS `vul_detection_result_finger`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `vul_detection_result_finger` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scanTime` datetime NOT NULL,
  `ip` varchar(15) NOT NULL,
  `url` text NOT NULL,
  `finger` varchar(255) NOT NULL,
  `uuid` varchar(255) NOT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `uuid_foreign2` (`uuid`) USING BTREE,
  CONSTRAINT `uuid_foreign2` FOREIGN KEY (`uuid`) REFERENCES `vul_detection_result` (`uuid`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vul_detection_result_finger`
--

LOCK TABLES `vul_detection_result_finger` WRITE;
/*!40000 ALTER TABLE `vul_detection_result_finger` DISABLE KEYS */;
INSERT INTO `vul_detection_result_finger` VALUES (1,'2024-03-23 11:36:54','127.0.0.1','http://127.0.0.1:8080','Tomcat','aaa');
/*!40000 ALTER TABLE `vul_detection_result_finger` ENABLE KEYS */;
UNLOCK TABLES;

-- ----------------------------
-- Table structure for tb_brute_force_record
-- ----------------------------
DROP TABLE IF EXISTS `tb_brute_force_record`;
CREATE TABLE `tb_brute_force_record`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键id',
  `uuid` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'uuid',
  `agent_ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'Agent的IP地址',
  `atk_ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '攻击者的IP地址',
  `scan_time` datetime NULL DEFAULT NULL COMMENT '扫描时间',
  `atk_type` int(11) NULL DEFAULT NULL COMMENT '威胁类型',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Records of tb_brute_force_record
-- ----------------------------
INSERT INTO `tb_brute_force_record` VALUES (1, 'qqqa', '127.0.0.2', '211.179.234.140', '2024-01-29 12:20:07', 1);
INSERT INTO `tb_brute_force_record` VALUES (2, 'asdf', '127.0.0.1', '218.92.0.93', '2024-01-29 12:20:07', 1);
INSERT INTO `tb_brute_force_record` VALUES (3, 'zzxzz', '127.0.0.1', '64.227.151.242', '2024-01-29 12:20:07', 1);

-- ----------------------------
-- Table structure for tb_privilege_escalation
-- ----------------------------
DROP TABLE IF EXISTS `tb_privilege_escalation`;
CREATE TABLE `tb_privilege_escalation`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键',
  `uuid` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'uuid',
  `agent_ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT 'Agent的ip地址',
  `atk_ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '攻击者的ip地址',
  `atk_time` datetime NULL DEFAULT NULL COMMENT '攻击时间',
  `atk_type` int(11) NULL DEFAULT NULL COMMENT '攻击类型',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 33 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Records of tb_privilege_escalation
-- ----------------------------
INSERT INTO `tb_privilege_escalation` VALUES (29, NULL, '43.139.3.146', '36.148.125.103', '2024-04-06 20:45:50', 2);
INSERT INTO `tb_privilege_escalation` VALUES (30, NULL, '43.139.3.146', '36.148.125.103', '2024-04-06 20:46:02', 2);
INSERT INTO `tb_privilege_escalation` VALUES (31, NULL, '43.139.3.146', '36.148.125.103', '2024-04-06 20:46:08', 2);
INSERT INTO `tb_privilege_escalation` VALUES (32, NULL, '43.139.3.147', '36.148.125.103', '2024-04-06 20:46:15', 2);

--
-- Table structure for table `windows_security_checks`
--

DROP TABLE IF EXISTS `windows_security_checks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `windows_security_checks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `check_name` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `details` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `adjustment_requirement` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `instruction` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `status` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `last_checked` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `uuid` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `windows_security_checks`
--

LOCK TABLES `windows_security_checks` WRITE;
/*!40000 ALTER TABLE `windows_security_checks` DISABLE KEYS */;
/*!40000 ALTER TABLE `windows_security_checks` ENABLE KEYS */;
UNLOCK TABLES;

DROP TABLE IF EXISTS `scheduler_task`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `scheduler_task` (
    `job_id` VARCHAR(191) PRIMARY KEY,
    `job_class` VARCHAR(128),
    `exec_strategy` VARCHAR(128),
    `expression` VARCHAR(50),
    `create_time` TIMESTAMP,
    `start_time` TIMESTAMP,
    `end_time` TIMESTAMP,
    `taskDescription` VARCHAR(191),
    `exception` TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
    `excute_times` INT,
    `update_timestamp` TIMESTAMP,
    `start_timestamp` TIMESTAMP,
    `process_time` FLOAT,
    `retval` TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
    `status` VARCHAR(128)
);


/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;



-- Dump completed on 2024-04-22 16:00:21
