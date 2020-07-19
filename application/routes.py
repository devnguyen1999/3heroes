import os, uuid, time, json, zipfile
from flask import render_template, request, url_for, send_from_directory, redirect, session
from shutil import copyfile, rmtree
from datetime import datetime

from application import app, basedir, dropzone, mysql
from application.handle.analyze import analyze
from application.handle.checkAPK import checkAPK
from application.handle.checkZIP import checkZIP
from application.handle.getMD5 import getMD5


@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        file = request.files['file']

        id = str(uuid.uuid4())
        extension = os.path.splitext(file.filename)[1]

        file.save(os.path.join(app.config['TEMPORARY_PATH'], id + extension))
        
        session['id'] = id
        session['extension'] = extension
    return render_template('home.html')

@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    return render_template('contact.html')

@app.route('/handle', methods=['GET', 'POST'])
def handle():
    if 'id' not in session:
        return redirect(url_for('home'))
    elif session['extension'] == '.apk':
        id = session['id']
        extension = session['extension']
        tempPath =  os.path.join(app.config['TEMPORARY_PATH'], id + extension)
        if checkAPK(tempPath):
            md5 = getMD5(tempPath)
            if md5 != False:
                connect = mysql.connect()
                cursor = connect.cursor()
                cursor.execute("SELECT * FROM tbl_apkinfo WHERE md5 = %s", md5)
                data = cursor.fetchall()
                connect.close()
                if len(data) == 0:
                    if analyze(tempPath) != False:
                        copyfile(tempPath, os.path.join(app.config['UPLOADED_PATH'], md5 + extension))
                        os.remove(tempPath)
                        session.pop('id', None)
                        session.pop('extension', None)
                        return redirect(url_for('resultapk', md5 = md5))
                    else:
                        session.pop('id', None)
                        session.pop('extension', None)
                        os.remove(tempPath)
                        return redirect(url_for('apkinvalid', id = id))
                else:
                    connect = mysql.connect()
                    cursor = connect.cursor()
                    timeOfSubmit = datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S")
                    cursor.execute("UPDATE tbl_apkinfo SET lastSubmission = %s WHERE md5 = %s", (timeOfSubmit, md5))
                    connect.commit()
                    connect.close()
                    session.pop('id', None)
                    session.pop('extension', None)
                    os.remove(tempPath)
                    return redirect(url_for('resultapk', md5=md5))
            else:
                session.pop('id', None)
                session.pop('extension', None)
                os.remove(tempPath)
                return redirect(url_for('apkinvalid', id = id))
        else:
            session.pop('id', None)
            session.pop('extension', None)
            os.remove(tempPath)
            return redirect(url_for('apkinvalid', id = id))
    elif session['extension'] == '.zip':
        id = session['id']
        extension = session['extension']
        tempPathZIP =  os.path.join(app.config['TEMPORARY_PATH'], id + extension)
        if checkZIP(tempPathZIP):
            zipFile= zipfile.ZipFile(tempPathZIP)
            zipFile.extractall(os.path.join(app.config['TEMPORARY_PATH'], id))
            zipFile.close()
            nameArr = []
            md5Arr = []
            tempPathFolder = os.path.join(app.config['TEMPORARY_PATH'], id)
            dirs = os.listdir(tempPathFolder)
            for file in dirs:
                tempPath = os.path.join(app.config['TEMPORARY_PATH'], id) + '/' + file
                if checkAPK(tempPath):
                    md5 = getMD5(tempPath)
                    extensionInFolder = os.path.splitext(file)[1]
                    if md5 != False:
                        connect = mysql.connect()
                        cursor = connect.cursor()
                        cursor.execute("SELECT * FROM tbl_apkinfo WHERE md5 = %s", (md5))
                        data = cursor.fetchall()
                        connect.close()
                        if len(data) == 0:
                            if analyze(tempPath) != False:
                                copyfile(tempPath, os.path.join(app.config['UPLOADED_PATH'], md5 + extensionInFolder))
                                nameArr.append (file)
                                md5Arr.append (md5)
                            else:
                                nameArr.append (file)
                                md5Arr.append (None)
                        else:
                            connect = mysql.connect()
                            cursor = connect.cursor()
                            timeOfSubmit = datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S")
                            cursor.execute("UPDATE tbl_apkinfo SET lastSubmission = %s WHERE md5 = %s", (timeOfSubmit, md5))
                            connect.commit()
                            connect.close()
                            nameArr.append (file)
                            md5Arr.append (md5)
                    else:
                        nameArr.append (file)
                        md5Arr.append (None)
                else:
                    nameArr.append (file)
                    md5Arr.append (None)
            session.pop('id', None)
            session.pop('extension', None)
            rmtree(tempPathFolder)
            os.remove(tempPathZIP)
            session['nameArr'] = nameArr
            session['md5Arr'] = md5Arr
            return redirect(url_for('resultzip', id = id))
        else:
            session.pop('id', None)
            session.pop('extension', None)
            os.remove(tempPathZIP)


@app.route('/resultzip/<id>', methods=['GET', 'POST'])
def resultzip(id):
    nameArr = session['nameArr']
    md5Arr = session['md5Arr']
    print(nameArr)
    session.pop('nameArr', None)
    session.pop('md5Arr', None)
    return render_template('resultzip.html', nameArr = nameArr, md5Arr = md5Arr)
@app.route('/resultapk/<md5>', methods=['GET', 'POST'])
def resultapk(md5):
    connect = mysql.connect()
    cursor = connect.cursor()
    cursor.execute("SELECT * FROM tbl_apkinfo WHERE md5 = %s", (md5))
    data = cursor.fetchall()
    connect.close()
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
            'mainActivity': element[15],
            'certificate': json.loads(element[16]),
            'certificateIssuer': json.loads(element[17]),
            'certificateSubject': json.loads(element[18]),
            'declaredPermissions': json.loads(element[19]),
            'requestedPermissions': json.loads(element[20]),
            'activities': json.loads(element[21]),
            'services': json.loads(element[22]),
            'providers': json.loads(element[23]),
            'receivers': json.loads(element[24])
        }
    return render_template('resultapk.html', apkinfo = apkinfo)

@app.route('/downloadxml/<md5>.xml')
def downloadxml(md5):
    return send_from_directory(os.path.join(app.config['OUTPUT_PATH']), md5 + '.xml', as_attachment=True)

@app.route('/apkinvalid/<id>', methods=['GET', 'POST'])
def apkinvalid(id):
    return render_template('apkinvalid.html')

@app.route('/zipinvalid<id>', methods=['GET', 'POST'])
def zipinvalid(id):
    return render_template('apkinvalid.html')