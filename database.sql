DROP DATABASE IF EXISTS 3heroes;
CREATE DATABASE IF NOT EXISTS 3heroes;
USE 3heroes;
CREATE TABLE tbl_apkinfo (
	md5 VARCHAR(175) NOT NULL,
	appName VARCHAR(50) NULL,
	fileSize INT NULL,
	analysisTime FLOAT(10,5) NULL,
	sha1 VARCHAR(200) NOT NULL UNIQUE,
	sha256 VARCHAR(225) NOT NULL UNIQUE,
	sha512 VARCHAR(250) NOT NULL UNIQUE,
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



DELIMITER //
CREATE DEFINER = root@localhost PROCEDURE addApkInfo(
	IN md5 VARCHAR(175),
	IN appName VARCHAR(50),
	IN fileSize INT,
	IN analysisTime FLOAT(10,5),
	IN sha1 VARCHAR(200),
	IN sha256 VARCHAR(225),
	IN sha512 VARCHAR(250),
	IN timeOfSubmit DATETIME,
	IN package VARCHAR(50),
	IN androidversionCode VARCHAR(50),
	IN androidversionName VARCHAR(50),
	IN minSDKVersion TINYINT,
	IN maxSDKVersion TINYINT,
	IN targetSDKVersion TINYINT,
	IN mainActivity VARCHAR(50),
	IN certificateAttributes JSON,
	IN certificateIssuer JSON,
	IN certificateSubject JSON,
	IN declaredPermissions JSON,
	IN requestedPermissions JSON,
	IN activities JSON,
	IN services JSON,
	IN providers JSON,
	IN receivers JSON
)
BEGIN
	INSERT INTO tbl_apkinfo
	(
		md5,
		appName,
		fileSize,
		analysisTime,
		sha1,
		sha256,
		sha512,
		firstSubmission,
		lastSubmission,
		package,
		androidversionCode,
		androidversionName,
		minSDKVersion,
		maxSDKVersion,
		targetSDKVersion,
		mainActivity,
		certificateAttributes,
		certificateIssuer,
		certificateSubject,
		declaredPermissions,
		requestedPermissions,
		activities,
		services,
		providers,
		receivers
	)
	VALUES
	(
		md5,
		appName,
		fileSize,
		analysisTime,
		sha1,
		sha256,
		sha512,
		timeOfSubmit,
		timeOfSubmit,
		package,
		androidversionCode,
		androidversionName,
		minSDKVersion,
		maxSDKVersion,
		targetSDKVersion,
		mainActivity,
		certificateAttributes,
		certificateIssuer,
		certificateSubject,
		declaredPermissions,
		requestedPermissions,
		activities,
		services,
		providers,
		receivers
	);
END //
DELIMITER ;



DELIMITER //
CREATE DEFINER = root@localhost PROCEDURE updateTimeOfSubmit(
	IN md5 VARCHAR(175),
	IN timeOfSubmit DATETIME
)
BEGIN
	UPDATE tbl_apkinfo SET lastSubmission = timeOfSubmit WHERE md5 = md5;
END //
DELIMITER ;



DELIMITER //
CREATE DEFINER = root@localhost PROCEDURE getApkInfo(
	IN md5 VARCHAR(175)
)
BEGIN
    SELECT * FROM tbl_apkinfo WHERE md5 = md5;
END //
DELIMITER ;