import hashlib
from androguard.core.bytecodes.apk import APK
from androguard.util import get_certificate_name_string
from asn1crypto import x509, keys
def getMD5(path):
    try:
        a = APK(path)
        hashfunctions = dict(md5=hashlib.md5)
        certs = set(a.get_certificates_der_v3() + a.get_certificates_der_v2() + [a.get_certificate_der(x) for x in a.get_signature_names()])
        for cert in certs:
            for k, v in hashfunctions.items():
                md5 = v(cert).hexdigest()
        return md5
    except:
        return False