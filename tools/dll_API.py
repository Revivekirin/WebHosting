#dll파일과 임포트한 함수를 나열
import pefile
import sys

mal_file = sys.argv[1]
pe = pefile.PE(mal_file)

if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print("%s".format(entry.dll)) 
        for impo in entry.imports:
            if imp.name != None:
                print("\t%s".format(imp.name))
            else:
                print("\tord(%s)".format(str(imp.ordinal))
        print('\n'))
        