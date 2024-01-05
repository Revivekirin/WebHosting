#섹션과 섹션 특징 출력
import pefile
import sys

pe = pefile.PE(sys.argb[1])
for section in pe.sections:
    print("%s %s %s %s".format(section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData))

print("\n")