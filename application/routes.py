import os, uuid, hashlib
from application import app, basedir, dropzone
from flask import render_template, request, url_for, redirect, send_from_directory
from androguard.cli import androaxml_main
from androguard.core.bytecodes.apk import APK
from androguard.util import get_certificate_name_string
from asn1crypto import x509, keys

@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    id = str(uuid.uuid4())
    return render_template('home.html', id=id)
@app.route('/upload/<id>', methods=['GET', 'POST'])
def upload(id):
    if request.method == 'POST':
        file = request.files['file']
        file.save(os.path.join(app.config['UPLOADED_PATH'], id + '.apk'))
    return 'Upload successful!'
@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    return render_template('contact.html')
@app.route('/result/<id>', methods=['GET', 'POST'])
def result(id):
    # Keep the list of hash functions in sync with cli/entry_points.py:sign
    hashfunctions = dict(md5=hashlib.md5,
                         sha1=hashlib.sha1,
                         sha256=hashlib.sha256,
                         sha512=hashlib.sha512
                         )

    a = APK(os.path.join(app.config['UPLOADED_PATH'], id + '.apk'))
    
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
    return render_template('result.html', id = id, apkinfo = apkinfo, certificates = certificates, hashfuncs = hashfuncs)


@app.route('/downloadxml/<id>')
def downloadxml(id):

    androaxml_main(os.path.join(app.config['UPLOADED_PATH'], id + '.apk'), os.path.join(app.config['OUTPUT_PATH'], id + '.xml') )

    return send_from_directory(os.path.join(app.config['OUTPUT_PATH']), id + '.xml', as_attachment=True)