import os, uuid, hashlib
from application import app, basedir, dropzone, mysql
from flask import render_template, request, url_for, send_from_directory, redirect, session
from androguard.cli import androaxml_main
from androguard.core.bytecodes.apk import APK
from androguard.util import get_certificate_name_string
from asn1crypto import x509, keys
from time import process_time

@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    # set session cho file apk
    if 'md5' not in session:
        session['md5'] = []
    md5 = session['md5']

    if request.method == 'POST':
        file = request.files['file']

        # tao id cho file
        id = str(uuid.uuid4())

        # luu file vao thu mu upload voi ten file la id vua tao
        file.save(os.path.join(app.config['UPLOADED_PATH'], id + '.apk'))

        # lay md5 cua file
        hashfunctions = dict(md5=hashlib.md5)
        a = APK(os.path.join(app.config['UPLOADED_PATH'], id + '.apk'))
        certs = set(a.get_certificates_der_v3() + a.get_certificates_der_v2() + [a.get_certificate_der(x) for x in a.get_signature_names()])
        for cert in certs:
            for k, v in hashfunctions.items():
                md5 = v(cert).hexdigest()
        
        # gan gia tri md5 vao session
        session['md5'] = md5

        # doi ten file lai thanh <md5>.apk
        os.chdir(os.path.join(app.config['UPLOADED_PATH']))
        os.rename(id + '.apk', md5 + '.apk')
    return render_template('home.html')
@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    return render_template('contact.html')
@app.route('/result', methods=['GET', 'POST'])
def result():
    # redirect ve trang chu neu chua co file nao duoc upload
    if 'md5' not in session or session['md5'] == []:
        return redirect(url_for('home'))
    
    # lay gia tri md5 va remove gia tri md5 trong session
    md5 = session['md5']
    session.pop('md5', None)

    # danh sach cac ham hash
    hashfunctions = dict(md5=hashlib.md5,
                         sha1=hashlib.sha1,
                         sha256=hashlib.sha256,
                         sha512=hashlib.sha512
                         )
    #tao moc thoi gian
    start = process_time()
    #chi dinh file can phan tich
    a = APK(os.path.join(app.config['UPLOADED_PATH'], md5 + '.apk'))
    
    # lay thong tin chung chi cua file
    certs = set(a.get_certificates_der_v3() + a.get_certificates_der_v2() + [a.get_certificate_der(x) for x in a.get_signature_names()])

    for cert in certs:
        x509_cert = x509.Certificate.load(cert)
        
        certificates = {
            'issuer': {
                'commonName': 'None',
                'organizationName': 'None',
                'organizationalUnitName': 'None',
                'countryName': 'None',
                'stateOrProvinceName': 'None',
                'localityName': 'None'
            },
            'subject': {
                'commonName': 'None',
                'organizationName': 'None',
                'organizationalUnitName': 'None',
                'countryName': 'None',
                'stateOrProvinceName': 'None',
                'localityName': 'None'
            },
            'validFrom': x509_cert['tbs_certificate']['validity']['not_before'].native,
            'validTo': x509_cert['tbs_certificate']['validity']['not_after'].native,
            'serialNumber': hex(x509_cert.serial_number),
            'hashAlgorithm': x509_cert.hash_algo,
            'signatureAlgorithm': x509_cert.signature_algo
        }
        strIssuer = get_certificate_name_string(x509_cert.issuer, short=False)
        strSubject = get_certificate_name_string(x509_cert.subject, short=False)
        
        arrIssuer = strIssuer.split(',')
        for i in arrIssuer:
            if i.lstrip().split('=')[0] == 'commonName':
                certificates['issuer']['commonName'] = i.lstrip().split('=')[1]
            elif i.lstrip().split('=')[0] == 'organizationName':
                certificates['issuer']['organizationName'] = i.lstrip().split('=')[1]
            elif i.lstrip().split('=')[0] == 'organizationalUnitName':
                certificates['issuer']['organizationalUnitName'] = i.lstrip().split('=')[1]
            elif i.lstrip().split('=')[0] == 'countryName':
                certificates['issuer']['countryName'] = i.lstrip().split('=')[1]
            elif i.lstrip().split('=')[0] == 'stateOrProvinceName':
                certificates['issuer']['stateOrProvinceName'] = i.lstrip().split('=')[1]
            elif i.lstrip().split('=')[0] == 'localityName':
                certificates['issuer']['localityName'] = i.lstrip().split('=')[1]
        
        arrSubject = strSubject.split(',')
        for i in arrSubject:
            if i.lstrip().split('=')[0] == 'commonName':
                certificates['subject']['commonName'] = i.lstrip().split('=')[1]
            elif i.lstrip().split('=')[0] == 'organizationName':
                certificates['subject']['organizationName'] = i.lstrip().split('=')[1]
            elif i.lstrip().split('=')[0] == 'organizationalUnitName':
                certificates['subject']['organizationalUnitName'] = i.lstrip().split('=')[1]
            elif i.lstrip().split('=')[0] == 'countryName':
                certificates['subject']['countryName'] = i.lstrip().split('=')[1]
            elif i.lstrip().split('=')[0] == 'stateOrProvinceName':
                certificates['subject']['stateOrProvinceName'] = i.lstrip().split('=')[1]
            elif i.lstrip().split('=')[0] == 'localityName':
                certificates['subject']['localityName'] = i.lstrip().split('=')[1]

        # lay gia trin trong danh sach cac ham hash
        for k, v in hashfunctions.items():
            if k == 'md5':
                md5 = v(cert).hexdigest()
            elif k == 'sha1':
                sha1 = v(cert).hexdigest()
            elif k == 'sha256':
                sha256 = v(cert).hexdigest()
            elif k == 'sha512':
                sha512 = v(cert).hexdigest()
        hashfuncs = {
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'sha512': sha512
        }
    #ket thuc thoi gian phan tich
    stop = process_time()
    print("Elapsed time during the whole program in seconds:", stop - start)
    
    apkinfo = {
        'appName': a.get_app_name(),
        'fileSize': os.stat(a.get_filename()).st_size,

        'package': a.get_package(),
        'androidversionCode': a.get_androidversion_code(),
        'androidversionName': a.get_androidversion_name(),
        'minSDKVersion': a.get_min_sdk_version(),
        'maxSDKVersion': a.get_max_sdk_version(),
        'targetSDKVersion': a.get_target_sdk_version(),

        'declaredPermissions': a.get_declared_permissions(),

        'requestedPermissions': a.get_permissions(),

        'mainActivity': a.get_main_activity(),
        'activities': a.get_activities(),

        'services': a.get_services(),

        'receivers': a.get_receivers(),
        
        'providers': a.get_providers()
    }

    appName = a.get_app_name()
    fileSize = os.stat(a.get_filename()).st_size
    md5 = md5
    sha1 = sha1
    sha256 = sha256
    sha512 = sha512
    firstSubmission = '2020-06-09 22:22:22'
    lastSubmission = '2020-06-09 22:22:22'
    package = a.get_package()
    androidversionCode = a.get_androidversion_code()
    androidversionName = a.get_androidversion_name()
    minSDKVersion = a.get_min_sdk_version()
    maxSDKVersion = a.get_max_sdk_version()
    targetSDKVersion = a.get_target_sdk_version()
    mainActivity = a.get_main_activity()

    # conn = mysql.connect()
    # cursor = conn.cursor()
    # cursor.callproc('addApkInfo',(md5, appName, fileSize, sha1, sha256, sha512, firstSubmission, lastSubmission, package, androidversionCode, androidversionName, minSDKVersion, maxSDKVersion, targetSDKVersion, mainActivity))
    # data = cursor.fetchall()
    # if len(data) == 0:
    #     conn.commit()
    return render_template('result.html', md5 = md5, apkinfo = apkinfo, certificates = certificates, hashfuncs = hashfuncs)


@app.route('/downloadxml/<id>')
def downloadxml(id):

    androaxml_main(os.path.join(app.config['UPLOADED_PATH'], id + '.apk'), os.path.join(app.config['OUTPUT_PATH'], id + '.xml') )

    return send_from_directory(os.path.join(app.config['OUTPUT_PATH']), id + '.xml', as_attachment=True)