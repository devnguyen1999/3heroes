import os, uuid, time
from application import app, basedir, dropzone, mysql
from application.analyze import analyze
from application.checkAPK import checkAPK
from application.getMD5 import getMD5
from flask import render_template, request, url_for, send_from_directory, redirect, session
import zipfile
from shutil import copyfile
from datetime import datetime

@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'id' not in session:
        session['id'] = []
        session['extension'] = []

    if request.method == 'POST':
        file = request.files['file']
        
        id = str(uuid.uuid4())

        extension = os.path.splitext(file.filename)[1]
        
        if extension == '.apk':
            file.save(os.path.join(app.config['TEMPORARY_PATH'], id + extension))

            session['id'] = id
            session['extension'] = extension
        elif extension == '.zip':
            file.save(os.path.join(app.config['TEMPORARY_PATH'], id + extension))
            
            session['id'] = id
            session['extension'] = extension

            zipFile= zipfile.ZipFile(os.path.join(app.config['TEMPORARY_PATH'], id + extension))
            zipFile.extractall(os.path.join(app.config['TEMPORARY_PATH'], id))
            zipFile.close()
    return render_template('home.html')
@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    return render_template('contact.html')
@app.route('/handle', methods=['GET', 'POST'])
def handle():
    if 'id' not in session or session['id'] == []:
        return redirect(url_for('home'))
    elif session['extension'] == '.apk':
        id = session['id']
        extension = session['extension']
        tempPath =  os.path.join(app.config['TEMPORARY_PATH'], id + extension)
        if checkAPK(tempPath):
            md5 = getMD5(tempPath)
            if md5 != False:
                timestamp = time.time()
                dateTime = datetime.fromtimestamp(timestamp)
                submitTime = dateTime.strftime("%Y-%m-%d %H:%M:%S")
                connect = mysql.connect()
                cursor = connect.cursor()
                cursor.callproc('checkFileApk', (md5, submitTime))
                data = cursor.fetchall()
                connect.close()
                if len(data) == 0:
                    if analyze(tempPath) != False:
                        copyfile(tempPath, os.path.join(app.config['UPLOADED_PATH'], md5 + extension))
                        os.remove(tempPath)
                        session.pop('id', None)
                        session.pop('extension', None)
                        return redirect(url_for('resultapk', md5=md5))
                    else:
                        session.pop('id', None)
                        session.pop('extension', None)
                        os.remove(tempPath)
                        return redirect(url_for('apkinvalid'))
                else:
                    session.pop('id', None)
                    session.pop('extension', None)
                    os.remove(tempPath)
                    return redirect(url_for('resultapk', md5=md5))
            else:
                session.pop('id', None)
                session.pop('extension', None)
                os.remove(tempPath)
                return redirect(url_for('apkinvalid'))
        else:
            session.pop('id', None)
            session.pop('extension', None)
            os.remove(tempPath)
            return redirect(url_for('apkinvalid'))
    elif session['extension'] == '.zip':
        id = session['id']
        dirs = os.listdir(os.path.join(app.config['TEMPORARY_PATH'], id))
        for file in dirs:
            if checkAPK(os.path.join(app.config['TEMPORARY_PATH'], id) + '/' + file):
                if getMD5(os.path.join(app.config['TEMPORARY_PATH'], id) + '/' + file) is not False:
                    md5 = getMD5(os.path.join(app.config['TEMPORARY_PATH'], id) + '/' + file)
                    
                    if analyze(os.path.join(app.config['TEMPORARY_PATH'], id) + '/' + file) is not False:
                        analyze(os.path.join(app.config['TEMPORARY_PATH'], id) + '/' + file)
                        extension = os.path.splitext(file)[1]
                        copyfile(os.path.join(app.config['TEMPORARY_PATH'], id) + '/' + file, os.path.join(app.config['UPLOADED_PATH'], md5 + extension))
                        os.remove(os.path.join(app.config['TEMPORARY_PATH'], id) + '/' + file)
                    
        
        session.pop('id', None)
        session.pop('extension', None)
        os.remove(os.path.join(app.config['TEMPORARY_PATH'], id + extension))
        return redirect(url_for('resultzip', id=id))

@app.route('/resultzip/<id>', methods=['GET', 'POST'])
def resultzip(id):
    dirs = os.listdir(os.path.join(app.config['TEMPORARY_PATH'], id))
    files = []
    for file in dirs:
        extension = os.path.splitext(file)[1]
        if extension == '.apk':
            print (file)
            files.append(file)
    return render_template('resultzip.html', files=files)
@app.route('/resultapk/<md5>', methods=['GET', 'POST'])
def resultapk(md5):
    connect = mysql.connect()
    cursor = connect.cursor()
    cursor.callproc('getApkInfo', [md5])
    data = cursor.fetchall()
    for element in data:
        apkinfo = {
            'md5': element[0],
            'appName': element[1],
            'fileSize': element[2],
            'analysisTime': element[3],
            'sha1': element[4],
            'sha256': element[5],
            'sha512': element[6],
            'firstSubmission': element[7],
            'lastSubmission': element[8],
            'package': element[9],
            'androidversionCode': element[10],
            'androidversionName': element[11],
            'minSDKVersion': element[12],
            'maxSDKVersion': element[13],
            'targetSDKVersion': element[14],
            'mainActivity': element[15]
        }
    
    cursor.callproc('getCertificate',[md5])
    data = cursor.fetchall()
    for element in data:
        certificate = {
            'md5': element[0],
            'validFrom': element[1],
            'validTo': element[2],
            'serialNumber': element[3],
            'hashAlgorithm': element[4],
            'signatureAlgorithm': element[5]
        }
    
    cursor.callproc('getCertificateIssuer',[md5])
    data = cursor.fetchall()
    for element in data:
        certificateIssuer = {
            'md5': element[0],
            'commonName': element[1],
            'organizationName': element[2],
            'organizationalUnitName': element[3],
            'countryName': element[4],
            'stateOrProvinceName': element[5],
            'localityName': element[6]
        }
    
    cursor.callproc('getCertificateSubject',[md5])
    data = cursor.fetchall()
    for element in data:
        certificateSubject = {
            'md5': element[0],
            'commonName': element[1],
            'organizationName': element[2],
            'organizationalUnitName': element[3],
            'countryName': element[4],
            'stateOrProvinceName': element[5],
            'localityName': element[6]
        }
    


    connect.close()
    
    return render_template('resultapk.html', apkinfo = apkinfo, certificate= certificate, certificateIssuer = certificateIssuer, certificateSubject = certificateSubject)

@app.route('/downloadxml/<md5>.xml')
def downloadxml(md5):
    return send_from_directory(os.path.join(app.config['OUTPUT_PATH']), md5 + '.xml', as_attachment=True)

@app.route('/apkinvalid', methods=['GET', 'POST'])
def apkinvalid():
    return render_template('apkinvalid.html')