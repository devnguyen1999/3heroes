DROP DATABASE IF EXISTS 3heroes;
CREATE DATABASE IF NOT EXISTS 3heroes;
USE 3heroes;
CREATE TABLE tbl_apkinfo (
	md5 VARCHAR(175) NOT NULL,
	appName VARCHAR(50) NULL,
	fileSize INT NULL,
	analysisTime FLOAT(10,5) NULL,
	sha1 VARCHAR(200) NULL,
	sha256 VARCHAR(225) NULL,
	sha512 VARCHAR(250) NULL,
	firstSubmission DATETIME NULL,
	lastSubmission DATETIME NULL,
	package VARCHAR(50) NULL,
	androidversionCode VARCHAR(50) NULL,
	androidversionName VARCHAR(50) NULL,
	minSDKVersion TINYINT NULL,
	maxSDKVersion TINYINT NULL,
	targetSDKVersion TINYINT NULL,
	mainActivity VARCHAR(50) NULL,
	certificateAttributes JSON NULL,
	certificateIssuer JSON NULL,
	certificateSubject JSON NULL,
	declaredPermissions JSON NULL,
	requestedPermissions JSON NULL,
	activities JSON NULL,
	services JSON NULL,
	providers JSON NULL,
	receivers JSON NULL,

	PRIMARY KEY (md5)
);