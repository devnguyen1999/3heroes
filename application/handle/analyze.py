import os, hashlib, time, json
from application import app, basedir, mysql
from androguard.cli import androaxml_main
from androguard.core.bytecodes.apk import APK
from androguard.util import get_certificate_name_string
from asn1crypto import x509, keys
from time import process_time
from datetime import datetime
def analyze(path):
    try:
        start = process_time()
        hashfunctions = dict(md5=hashlib.md5,
                            sha1=hashlib.sha1,
                            sha256=hashlib.sha256,
                            sha512=hashlib.sha512
                            )
        a = APK(path)
        
        certs = set(a.get_certificates_der_v3() + a.get_certificates_der_v2() + [a.get_certificate_der(x) for x in a.get_signature_names()])

        for cert in certs:
            x509_cert = x509.Certificate.load(cert)
            
            issuer = {
                'commonName': None,
                'organizationName': None,
                'organizationalUnitName': None,
                'countryName': None,
                'stateOrProvinceName': None,
                'localityName': None
            }
            subject = {
                'commonName': None,
                'organizationName': None,
                'organizationalUnitName': None,
                'countryName': None,
                'stateOrProvinceName': None,
                'localityName': None
            }

            strIssuer = get_certificate_name_string(x509_cert.issuer, short=False)
            strSubject = get_certificate_name_string(x509_cert.subject, short=False)
            
            arrIssuer = strIssuer.split(',')
            for i in arrIssuer:
                if i.lstrip().split('=')[0] == 'commonName':
                    issuer['commonName'] = i.lstrip().split('=')[1]
                elif i.lstrip().split('=')[0] == 'organizationName':
                    issuer['organizationName'] = i.lstrip().split('=')[1]
                elif i.lstrip().split('=')[0] == 'organizationalUnitName':
                    issuer['organizationalUnitName'] = i.lstrip().split('=')[1]
                elif i.lstrip().split('=')[0] == 'countryName':
                    issuer['countryName'] = i.lstrip().split('=')[1]
                elif i.lstrip().split('=')[0] == 'stateOrProvinceName':
                    issuer['stateOrProvinceName'] = i.lstrip().split('=')[1]
                elif i.lstrip().split('=')[0] == 'localityName':
                    issuer['localityName'] = i.lstrip().split('=')[1]
            
            arrSubject = strSubject.split(',')
            for i in arrSubject:
                if i.lstrip().split('=')[0] == 'commonName':
                    subject['commonName'] = i.lstrip().split('=')[1]
                elif i.lstrip().split('=')[0] == 'organizationName':
                    subject['organizationName'] = i.lstrip().split('=')[1]
                elif i.lstrip().split('=')[0] == 'organizationalUnitName':
                    subject['organizationalUnitName'] = i.lstrip().split('=')[1]
                elif i.lstrip().split('=')[0] == 'countryName':
                    subject['countryName'] = i.lstrip().split('=')[1]
                elif i.lstrip().split('=')[0] == 'stateOrProvinceName':
                    subject['stateOrProvinceName'] = i.lstrip().split('=')[1]
                elif i.lstrip().split('=')[0] == 'localityName':
                    subject['localityName'] = i.lstrip().split('=')[1]

            for k, v in hashfunctions.items():
                if k == 'md5':
                    md5 = v(cert).hexdigest()
                elif k == 'sha1':
                    sha1 = v(cert).hexdigest()
                elif k == 'sha256':
                    sha256 = v(cert).hexdigest()
                elif k == 'sha512':
                    sha512 = v(cert).hexdigest()

        
        md5 = md5

        appName = a.get_app_name()
        fileSize = os.stat(a.get_filename()).st_size
        sha1 = sha1
        sha256 = sha256
        sha512 = sha512
        timestamp = time.time()
        dateTime = datetime.fromtimestamp(timestamp)
        submitTime = dateTime.strftime("%Y-%m-%d %H:%M:%S")
        package = a.get_package()
        androidversionCode = a.get_androidversion_code()
        androidversionName = a.get_androidversion_name()
        minSDKVersion = a.get_min_sdk_version()
        maxSDKVersion = a.get_max_sdk_version()
        targetSDKVersion = a.get_target_sdk_version()
        mainActivity = a.get_main_activity()

        attributes = {
            'validFrom': x509_cert['tbs_certificate']['validity']['not_before'].native.strftime("%Y-%m-%d %H:%M:%S"),
            'validTo': x509_cert['tbs_certificate']['validity']['not_after'].native.strftime("%Y-%m-%d %H:%M:%S"),
            'serialNumber': hex(x509_cert.serial_number),
            'hashAlgorithm': x509_cert.hash_algo,
            'signatureAlgorithm': x509_cert.signature_algo
        }

        certificateAttributes = json.dumps(attributes)
        certificateIssuer = json.dumps(issuer)
        certificateSubject = json.dumps(subject)

        declaredPermissions = json.dumps(a.get_declared_permissions())

        requestedPermissions = json.dumps(a.get_permissions())

        activities = json.dumps(a.get_activities())

        services = json.dumps(a.get_services())

        receivers = json.dumps(a.get_receivers())
            
        providers = json.dumps(a.get_providers())



        stop = process_time()
        analysisTime = stop - start

        connect = mysql.connect()
        cursor = connect.cursor()

        cursor.callproc('addApkInfo', (md5, appName, fileSize, analysisTime, sha1, sha256, sha512, submitTime, package, androidversionCode, androidversionName, minSDKVersion, maxSDKVersion, targetSDKVersion, mainActivity, certificateAttributes, certificateIssuer, certificateSubject, declaredPermissions, requestedPermissions, activities, services, providers, receivers))

        connect.commit()
        connect.close()

        androaxml_main(path, os.path.join(app.config['OUTPUT_PATH'], md5 + '.xml'))
        return True
    except:
        return False
