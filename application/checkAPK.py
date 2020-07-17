import magic
from androguard.core.bytecodes.apk import APK
def checkAPK(path):
    try:
        checktype = magic.from_file(str(path),mime=True)
        if(checktype in ["application/zip", "application/java-archive"]):
            a = APK(path)
            if a.is_valid_APK:
                return True
            return False
    except:
        return False