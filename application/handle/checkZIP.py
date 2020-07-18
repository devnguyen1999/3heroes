import magic
def checkZIP(path):
    try:
        checktype = magic.from_file(str(path),mime=True)
        if(checktype in ["application/zip"]):
            return True
        return False
    except:
        return False