#파일유형구분
import magic

m = magic.open(magic.MAGIC_NONE)
m.load()
ftype = m.file(r'실행파일.exe')
print(ftype)

#result: PE32 executable (GUI) Intel 80386, for MS WIndows

