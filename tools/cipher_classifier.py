#암호해시파악
import hashlib

content = open(r"실행파일.exe", 'rb').read()
hashlib.md5(content).hexdigest() #md5
hashlib.sha256(content).hexdigest() #sha256
hashlib.sha1(content).hexdigest() #sha1
