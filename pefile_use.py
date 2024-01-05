import pefile
import hashlib
import sys
import os
import subprocess
import re
import datetime
from datetime import timezone
import collections
import math
import json



def calculate_entropy(file_path):
    # 파일 읽기
    with open(file_path, 'rb') as file:
        data = file.read()

    # 각 바이트 값의 발생 빈도를 계산
    byte_counters = collections.Counter(data)
    file_length = len(data)

    # 샤논 엔트로피 계산
    entropy = 0
    for count in byte_counters.values():
        # 각 바이트의 확률
        probability = count / file_length
        # 엔트로피 계산
        entropy -= probability * math.log2(probability)

    return entropy
  

def print_pe_header(file_path):
    try:
        pe = pefile.PE(file_path)

        # DOS Header
        print(f"\nDOS Header: ")
        print(f" e_magic: {hex(pe.DOS_HEADER.e_magic)}") # 4D 5A (MZ), PE파일 구조
        print(f" e_lfanew: {hex(pe.DOS_HEADER.e_lfanew)}") # IMAG_NT_HEADER 시작주소
        print(f"\nNT Header: ")
        print(f" Signature: {hex(pe.NT_HEADERS.Signature)}")
        
        # File Header
        print(f"\n File Header: ")
        print(f"  Machine: {hex(pe.FILE_HEADER.Machine)}") # ex) 014C-intel CPU
        print(f"  Number of Sections: {pe.FILE_HEADER.NumberOfSections}") # Section 개수
        #timestamp 출력을 위해 코드 추가
        #기존 코드 : print(f"  Time Date Stamp: {pe.FILE_HEADER.TimeDateStamp}") # 시간차이가 미래일 경우 악성코드일 수 있음
        timestamp = pe.FILE_HEADER.TimeDateStamp
        human_readable_timestamp = datetime.datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        print(f"  Time Date Stamp: {human_readable_timestamp}")
        # Size of Optional Header 생략
        print(f"  Characteristics: {hex(pe.FILE_HEADER.Characteristics)}") # 파일 형식 정보, 32bit - win32, 64bit - winnt.h 문서 참고
        
        # Optional Header
        print(f"\n Optional Header: ")
        # Magic 추가
        #print(f"  Magic: {hex(pe.OPTIONAL_HEADER.Magic)}")
        # Magic이 몇 비트 파일인지 수정
        magic = pe.OPTIONAL_HEADER.Magic
        if magic == 0x20b:
            print(" Magic: 0x20b, 64-bit File")
        elif magic == 0x10b:
            print(" Magic: 0x10b, 32-bit File")
        else:
            print(f" Magic: {hex(magic)}, Unknown architecture")
        # Size of code 추가
        print(f"  SizeOfCode: {hex(pe.OPTIONAL_HEADER.SizeOfCode)}")
        print(f"  Address Entry point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}") # 프로그램 시작 주소, 파일싫애시 Image Base + Address of Entry Point에서 시작
        # Base of code (RVA 시작주소) 추가
        print(f"  BaseOfCode: {hex(pe.OPTIONAL_HEADER.BaseOfCode)}")
        print(f"  Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}") # PE 파일이 메모리에 로드되는 시작 주소
        print(f"  Section Alignment: {pe.OPTIONAL_HEADER.SectionAlignment}") # 메모리에서 섹션의 최소 단위/ 패딩크기 유추 가능
        print(f"  File Alignment: {pe.OPTIONAL_HEADER.FileAlignment}") # 파일에서 섹션의 최소 단위
        print(f"  Size of Image: {pe.OPTIONAL_HEADER.SizeOfImage}") # PE파일이 메모리에 로딩될 때 전체 크기, File alignment의 배수
        # Size of header 추가
        print(f"  SizeOfHeaders: {pe.OPTIONAL_HEADER.SizeOfHeaders}")
        # Subsystem 추가
        print(f"  Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")

    except pefile.PEFormatError as e:
        print(f"Error: {e}")

        
def print_pe_section(file_path):
    try:

        pe = pefile.PE(file_path)

        sections = pe.sections

        for section in sections:
            
            # print(f" \nSection Name: {section.Name.decode().rstrip('\x00')}") # Ascii
            print("\nSection Name : {}".format(section.Name.decode().rstrip('\x00')))
            
            print(f" Virtual Size: {section.Misc_VirtualSize}") # 메모리 섹션 크기
            print(f" Virtual Address: {hex(section.VirtualAddress)}") # RVA, optinal header의 base of code와 동일, 실제주소: Image Base+RVA
            print(f" Raw Size: {section.SizeOfRawData}") # 파일에서의 섹션 크기
            print(f" Raw Address: {hex(section.PointerToRawData)}") # 파일에서 섹션 시작 위치
            print(f" Characteristics: {hex(section.Characteristics)}") # 섹션의 정보 표시 , ex) 60000020 -> 읽고 쓰기가 가능한 코드 섹션
    except pefile.PEFormatError as e:
        print(f"Error: {e}")

        
def print_imports_and_exports(file_path):
    try:

        pe = pefile.PE(file_path)

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            print('\nImported Functions:')
            for file in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"\n DLL: {file.dll.decode()}")
                for function in file.imports:
                    # 함수 이름이 없을 경우 dll파일의 ordinal number로 대체
                    print(f"  Function: {function.name.decode() if function.name else 'Ordinal ' + str(function.ordinal)}")

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            print("\nExported Functions:")
            for function in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print(f"  Function: {function.name.decode() if function.name else 'Ordinal ' + str(function.ordinal)}")

    except pefile.PEFormatError as e:
        print(f"Error: {e}")

        
def print_resource(file_path):
    try:
        pe = pefile.PE(file_path)

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            print("\nResource Information:")
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                resource_type_str = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, resource_type.struct.Id)  # ex) RT_ICON, RT_STRING, RT_BITMAP
                print(f" Resource Type: {resource_type_str}")
                for resource_entry in resource_type.directory.entries:
                    if hasattr(resource_entry, 'data'):
                        if hasattr(resource_entry.data, 'struct'):
                            print(f" Resource ID: {resource_entry.id}")
                            print(f" Size: {resource_entry.data.struct.Size}")
                            print(f" RVA: {hex(resource_entry.data.struct.OffsetToData)}")
                            offset = pe.get_offset_from_rva(resource_entry.data.struct.OffsetToData)
                            print(f" Offset: {hex(offset)}")
    except pefile.PEFormatError as e:
        print(f"Error: {e}")

        
def print_relocation(file_path):
    try:
        pe = pefile.PE(file_path)

        if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            print("Relocation Information:")

            for relocation in pe.DIRECTORY_ENTRY_BASERELOC:   # 각 block을 relocation에 할당
                # print(f"\nVirtual Address: ", hex(virtual_address))
                # print(f" Size of Blocks: {relocation_block}")

                for entry in relocation.entries: # 각 block의 entries(type, offset)출력
                    type = entry.type 
                    offset = entry.rva

                    print(f" Type: {type}")
                    print(f" Offset: {hex(offset)}")

        else:
            print("There are no relocation information.")

    except pefile.PEFormatError as e:
        print("Error: {e}")

        
def get_ascii_strings(raw_data, min_length):
    pattern = b'[\x20-\x7E]{' + str(min_length).encode() + b',}'
    return re.findall(pattern, raw_data)

def get_unicode_strings(raw_data, min_length):
    pattern = b'(?:[\x20-\x7E][\x00]){' + str(min_length).encode() + b',}'
    return re.findall(pattern, raw_data)

def is_valid_string(s):  
    # 바이트 타입인 경우, 문자열로 디코딩
    if isinstance(s, bytes):
        s = s.decode()

    #문자의 길이가 3자 이하인 경우 필터링
    if len(s) <= 3:
        return False

    # 정규 표현식을 사용하여 기본 패턴 검사
    if not re.match(r'^[a-zA-Z0-9\s.,;:\'\"!?()-]+$', s):
        return False

    # 영문자와 숫자가 아닌 문자가 일정 비율 이상인 경우 필터링
    non_alnum_chars = sum(not c.isalnum() for c in s)
    if non_alnum_chars / len(s) > 0.3:  # 예를 들어, 비문자/숫자가 30% 이상인 경우
        return False

    # 반복되는 문자가 일정 비율 이상인 경우 필터링 (예: 'wwwwwwwwwx')
    if len(set(s)) / len(s) < 0.4: 
        return False

    return True

# def print_strings(file_path, min_l=4):
#     try:
#         pe = pefile.PE(file_path)

#         print("\nStrings Analysis:")
#         for section in pe.sections:
#             raw_data = section.get_data()
#             ascii_strings = get_ascii_strings(raw_data, min_length=min_l)
#             unicode_strings = get_unicode_strings(raw_data, min_length=min_l)

#             section_name = section.Name.decode().rstrip('\x00')
#             print(f"\n Section: {section_name}")

#             if ascii_strings:
#                 print("  ASCII Strings:")
#                 for string in ascii_strings:
#                     decoded_string = string.decode()
#                     if is_valid_string(decoded_string):
#                         print(f"  {decoded_string}")

    #         if unicode_strings:
    #             print("\n Unicode Strings:")
    #             for string in unicode_strings:
    #                 #기존 코드
    #                 #print(f"  {string}")
    #                 #수정 코드
    #                 decoded_string = string.decode('utf-16le').rstrip('\x00')
    #                 if is_valid_string(decoded_string):
    #                     print(f"  {decoded_string}")
    #                 #요기까지

    # except pefile.PEFormatError as e:
    #     print(f"Error: {e}")

def print_strings(file_path, min_l=4):
    try:
        pe = pefile.PE(file_path)

        ascii_strings = []
        unicode_strings = []

        for section in pe.sections:
            raw_data = section.get_data()
            ascii_strings.extend(get_ascii_strings(raw_data, min_length=min_l))
            unicode_strings.extend(get_unicode_strings(raw_data, min_length=min_l))
        return ascii_strings, unicode_strings

    except pefile.PEFormatError as e:
        print(f"Error: {e}")

# 엔트리포인트 이전에 시작되는 TLS콜백 함수를 확인하여 디버깅 여부를 확인한다. / 보통 출력되는 값이 없어야 한다.
def print_tls(file_path):
    try:

        pe = pefile.PE(file_path)

        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            tls = pe.DIRECTORY_ENTRY_TLS.struct

            print("TLS Information")
            print(f" Start Address of Raw Data: {hex(tls.StartAddressOfRawData)}")
            print(f" End Address of Raw Data: {hex(tls.EndAddressOfRawData)}")
            print(f" Address of Callbacks: {hex(tls.AddressOfCallBacks)}")
            print(f" Characteristics: {hex(tls.Characteristics)}")

            if tls.AddressOfCallBacks:
                print("\nTLS Callbacks:")
                for callback_address in tls.AddressOfCallBacks:
                    print(hex(callback_address))

        else:
            print("No Tls information in PE file")

    except pefile.PEFormatError as e:
        print(f"Error: {e}")

def calc_hashes(file_path):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

            md5_hash = hashlib.md5(data).hexdigest()
            sha1_hash = hashlib.sha1(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
            
        return md5_hash, sha1_hash, sha256_hash
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
        return None

#imphash 값 계산
def calc_imphash(file_path):
    try:
        pe = pefile.PE(file_path)
        imphash = pe.get_imphash()
        print(imphash)
        return imphash
    except pefile.PEFormatError as e:
        print(f"Error: {e}")
        return None
            
#hash 값 출력
def print_hash(file_path):
    hash = calc_hashes(file_path)
    imphash = calc_imphash(file_path)
    
    if hash or imphash:
        md5_hash, sha1_hash, sha256_hash = hash
        print(f"Hashes: ")
        print(f"MD5 Hash: {md5_hash}")
        print(f"SHA-1 Hash: {sha1_hash}")
        print(f"SHA-256 Hash: {sha256_hash}")
        print(f"ImpHash: {imphash}\n")
    else:
        print("Failed to calculate hashes or imphash.")  

def find_exe_files(file_path):

    with open(file_path, 'rb') as file:
        content = file.read()

        signatures = ['4D5A', '4045']

    found_locations = {}

    for signature in signatures:
        signature_bytes = bytes.fromhex(signature)
        for i in range(len(content)):
            if content[i:i+len(signature_bytes)] == signature_bytes:
                location = i

                if location:
                    found_locations[signature] = location

    if len(found_locations):
        return print("MZ:",found_locations["4D5A"], " PE:", found_locations["4045"])
    else:
        return print("There are no additional .exe files")


# # _IMAGE_DIRECOTORY_RESOURCE에 embedded 된 .exe 파일을 찾음
# def contains_another_exe(file_path):
#     try:
#        pe = pefile.PE(file_path)

#        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
#            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
#                for resource_id in resource_type.directory.entries:
#                    for resource_lang in resource_id.directory.entries:
#                        # resource data 추출
#                        resource_data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)

#                        if b'.exe' in resource_data:
#                            return print(f"\nFile has another .exe extension which is {resource_id}")

#     except Exception as e:
#         print(f"Error analyzing {file_path}: {e}")
        
#     return print("\nThis file doesn't contain another .exe file")

# rich header 출력
def print_rich_header(file_path):

    pe = pefile.PE(file_path)

    rich_header = pe.parse_rich_header()
    if rich_header is not None:
        print("Rich Header Information: ")
        print(f"Key: {rich_header.keys}")
        if 'records' in rich_header:
            records = rich_header['records']
            print("Records:")
    
            for record in records:
                # Access individual elements in the record
                print(f"ID: {record.get('id', 'N/A')}, Version: {record.get('version', 'N/A')}, Count: {record.get('count', 'N/A')}")
    else:
        print("No 'records' key found in rich_header.")

def is_upx_packed(file_path):
    try:
        pe = pefile.PE(file_path, fast_load = True)

    except pefile.PEFormatError as e:
        print(f"Error: {e}")
        return False
    
    upx_signature = b'UPX!'
    overlay_start = pe.OPTIONAL_HEADER.SizeOfImage
    overlay_data = pe.get_memory_mapped_image()[overlay_start:]

    if upx_signature in overlay_data:
        upx_section_names = ['.UPX0', '.UPX1', '.UPX2', '.rsrc']
        print("File has UPX packing!")
        for section in pe.sections:
            decoded_name = section.Name.decode().strip('\x00')
            if decoded_name in upx_section_names and decoded_name != '.rsrc':
                return print(f"{decoded_name} exsist!")
    else: 
        print("File doesn't have UPX packing!")

        
    # # 특성 확인 (IMAGE_SECTION_HEADER) 
    # IMAGE_SCN_MEM_EXECUTE = 0x20000000
    # IMAGE_SCN_MEM_READ = 0x40000000
    # IMAGE_SCN_MEM_WRITE = 0x80000000

    # packed_characteristics = [
    #     IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    #     IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE,
    # ]

    # for section in pe.sections:
    #     if any(section.Characteristics & flag for flag in packed_characteristics):
    #         return True
        
    return False

    
def check_if_dll_or_exe(file_path):
    pe = pefile.PE(file_path)
    characteristics = pe.FILE_HEADER.Characteristics

    is_exe = characteristics & 0x0002 and not (characteristics & 0x2000)
    is_dll = characteristics & 0x2000

    if is_exe:
        print(f"{file_path} is an EXE file.")
    elif is_dll:
        print(f"{file_path} is a DLL file.")
    else:
        print(f"{file_path} type is unknown.")

def unpack_upx(file_path):
    try: 
        subprocess.run(['upx', '-d', file_path], check=True)
        print(f"Unpacking success!: {file_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error occur!: {e}")

def json_entropy(file_path):
    # 파일 읽기
    with open(file_path, 'rb') as file:
        data = file.read()

    # 각 바이트 값의 발생 빈도를 계산
    byte_counters = collections.Counter(data)
    file_length = len(data)

    # 샤논 엔트로피 계산
    entropy = 0
    for count in byte_counters.values():
        # 각 바이트의 확률
        probability = count / file_length
        # 엔트로피 계산
        entropy -= probability * math.log2(probability)

    return entropy

def json_pe_header(file_path):
    try:
        pe = pefile.PE(file_path)
        
        def format_timestamp(timestamp):
            timestamp_datetime = datetime.datetime.utcfromtimestamp(timestamp)
            return timestamp_datetime.strftime('%Y-%m-%d %H:%M:%S')
        
        header_info = {
            "Dos_Header": {
                "e_magic": hex(pe.DOS_HEADER.e_magic),
                "e_lfanew": hex(pe.DOS_HEADER.e_lfanew)
            },
            "NT Header": {
                "Signature": hex(pe.NT_HEADERS.Signature)
            },
            "File Header": {
                "Machine": hex(pe.FILE_HEADER.Machine), 
                "Number of Sections": pe.FILE_HEADER.NumberOfSections,
                "Time Date Stamp": format_timestamp(pe.FILE_HEADER.TimeDateStamp),
                "Characteristics": hex(pe.FILE_HEADER.Characteristics)
            },
            "Optional Header": {
                "Magic": hex(pe.OPTIONAL_HEADER.Magic),
                "SizeOfCode": hex(pe.OPTIONAL_HEADER.SizeOfCode),
                "Address Entry point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "BaseOfCode": hex(pe.OPTIONAL_HEADER.BaseOfCode),
                "Image Base": hex(pe.OPTIONAL_HEADER.ImageBase), 
                "Section Alignment": pe.OPTIONAL_HEADER.SectionAlignment, 
                "File Alignment": pe.OPTIONAL_HEADER.FileAlignment, 
                "Size of Image": pe.OPTIONAL_HEADER.SizeOfImage, 
                "SizeOfHeaders": pe.OPTIONAL_HEADER.SizeOfHeaders,
                "Subsystem": pe.OPTIONAL_HEADER.Subsystem
                }
            }  
        return header_info

    except pefile.PEFormatError as e:
        print(f"Error: {e}")
        
def json_pe_section(file_path):
    pe = pefile.PE(file_path)
    sections_info = []

    sections = pe.sections

    for section in sections:
        section_info = {
            "Name": section.Name.decode().rstrip('\x00'),
            "Virtual_Size": section.Misc_VirtualSize,
            "Virtual_Address": hex(section.VirtualAddress),
            "Raw_Size": section.SizeOfRawData,
            "Raw_Address": hex(section.PointerToRawData),
            "Characteristics": hex(section.Characteristics)
        }

        sections_info.append(section_info)

    return sections_info

def json_imports_and_exports(file_path):
    pe = pefile.PE(file_path)
    imports_info = []
    exports_info = []

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for file in pe.DIRECTORY_ENTRY_IMPORT:
            dll_info = {
                "DLL": file.dll.decode(),
                "Functions": [
                    {"Function": function.name.decode() if function.name else f"Ordinal {function.ordinal}"}
                    for function in file.imports
                ]
            }
            imports_info.append(dll_info)

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports_info = [
            {"Function": function.name.decode() if function.name else f"Ordinal {function.ordinal}"}
            for function in pe.DIRECTORY_ENTRY_EXPORT.symbols
        ]

    return {"Imported_Functions": imports_info, "Exported_Functions": exports_info}

def json_resource(file_path):
    pe = pefile.PE(file_path)
    resource_info = []

    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            resource_type_str = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, resource_type.struct.Id)
            resource_type_entry = {
                "Resource_Type": resource_type_str,
                "Resources": []
            }

            for resource_entry in resource_type.directory.entries:
                if hasattr(resource_entry, 'data') and hasattr(resource_entry.data, 'struct'):
                    resource_entry_info = {
                        "Resource_ID": resource_entry.id,
                        "Size": resource_entry.data.struct.Size,
                        "RVA": hex(resource_entry.data.struct.OffsetToData),
                        "Offset": hex(pe.get_offset_from_rva(resource_entry.data.struct.OffsetToData))
                    }
                    resource_type_entry["Resources"].append(resource_entry_info)

            resource_info.append(resource_type_entry)

    return resource_info

#계속 오류 발생
def json_relocation(file_path):
    pe = pefile.PE(file_path)
    relocation_info = []

    if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        for relocation in pe.DIRECTORY_ENTRY_BASERELOC.entries:
            relocation_entry_info = {
                "Virtual_Address": hex(relocation.directory.VirtualAddress),
                "Size_of_Blocks": relocation.directory.Size,
                "Entries": []
            }

            # Check if 'entries' is available in the current relocation object
            if hasattr(relocation, 'entries'):
                # Iterating over 'entries' only if it is present
                for entry in relocation.entries:
                    type_value = entry.type
                    offset_value = entry.rva

                    entry_info = {
                        "Type": type_value,
                        "Offset": hex(offset_value)
                    }

                    relocation_entry_info["Entries"].append(entry_info)

            relocation_info.append(relocation_entry_info)

    return relocation_info


# 엔트리포인트 이전에 시작되는 TLS콜백 함수를 확인하여 디버깅 여부를 확인한다. / 보통 출력되는 값이 없어야 한다.
def json_tls(file_path):
    tls_info = {}

    try:
        pe = pefile.PE(file_path)

        if hasattr(pe, "TLS_ENTRY_DIRECTORY"):
            tls = pe.TLS_ENTRY_DIRECTORY.struct

            tls_info = {
                "Start_Address_of_Raw_Data": hex(tls.StartAddressOfRawData),
                "End_Address_of_Raw_Data": hex(tls.EndAddressOfRawData),
                "Address_of_Callbacks": hex(tls.AddressOfCallbacks),
                "Characteristics": hex(tls.Characteristics)
            }

    except pefile.PEFormatError as e:
        print(f"Error: {e}")

    return tls_info

def json_hash(file_path):
    hash_info = {}

    hash = calc_hashes(file_path)
    imphash = calc_imphash(file_path)

    if hash and imphash:
        md5_hash, sha1_hash, sha256_hash = hash
        hash_info = {
            "MD5_Hash": md5_hash,
            "SHA1_Hash": sha1_hash,
            "SHA256_Hash": sha256_hash,
            "ImpHash": imphash
        }

    return hash_info

def all_pe_info(file_path):
    pe_info = {
        "Entropy": json_entropy(file_path),
        "PE_Header_Info": json_pe_header(file_path),
        "Sections": json_pe_section(file_path),
        "Imports_and_Exports": json_imports_and_exports(file_path),
        "Resource": json_resource(file_path),
        # "Relocation": json_relocation(file_path),
        "TLS": json_tls(file_path),
        "Hash": json_hash(file_path),
        "contains_another_exe": find_exe_files(file_path),
        "is_upx_packed": is_upx_packed(file_path),
        "file_type": check_if_dll_or_exe(file_path)
    }
    return pe_info
       
def save_json_file(json_data, json_file_path):
    def convert_to_serializable(obj):
        try:
            # Try to serialize the object
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            # If a circular reference error occurs, convert to string representation
            return repr(obj)

    with open(json_file_path, 'w') as json_file:
        json.dump(json_data, json_file, default=convert_to_serializable, indent=4)
        
def save_json_result():
    json_output_path = input("Enter the path to save the JSON files: ")
    
    try:
        pe_info = all_pe_info(file_path)
        ascii_strings, unicode_strings = print_strings(file_path)

        file_name = os.path.splitext(os.path.basename(file_path))[0]
        json_file_name = f"{file_name}_pe_info.json"
        ascii_file_name = f"{file_name}_ascii_strings.json"
        unicode_file_name = f"{file_name}_unicode_strings.json"
        
        json_file_path = os.path.join(json_output_path, json_file_name)
        ascii_file_path = os.path.join(json_output_path, ascii_file_name)
        unicode_file_path = os.path.join(json_output_path, unicode_file_name)
        
        save_json_file(pe_info, json_file_path)
        save_json_file(unicode_strings, unicode_file_path)
        save_json_file(ascii_strings, ascii_file_path)
        
        print("\nJSON files created successfully.{json_file_path}")

    except pefile.PEFormatError as e:
        print(f"Save Json Error: {e}")
        
def swap_endianness(data, byte_size):
    # 데이터를 바이트 배열로 변환
    byte_data = bytearray.fromhex(data)

    # 4바이트
    
    if byte_size == 4:
        byte_data.reverse()

    # 2바이트
    elif byte_size == 2:
        byte_data[0:2], byte_data[2:4] = byte_data[2:4], byte_data[0:2]

    else:
        raise ValueError("byte error.")

    # 엔디안 전환 후, 16진수 문자열로 반환
    swapped_data = ''.join(format(byte, '02X') for byte in byte_data)

    return swapped_data

def get_data_directory_offset(pe, data_directory_index):
    try:
        # OPTIONAL_HEADER에 액세스하여 데이터 디렉터리의 정보를 가져옴
        data_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[data_directory_index]

        # 데이터 디렉터리의 offset 값을 반환
        return data_directory.VirtualAddress

    except Exception as e:
        print(f"error: {str(e)}")
        return None

def print_certificate_info(pe):
    # CERTIFICATE Table의 offset 및 size 가져오기
    certificate_offset = get_data_directory_offset(pe, pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'])
    certificate_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

    if certificate_offset and certificate_size:
        print(f"CERTIFICATE_TABLE offset: 0x{certificate_offset:X}")
        print(f"CERTIFICATE_TABLE size: 0x{certificate_size:X}")

        # CERTIFICATE Table 데이터 가져오기
        certificate_data = pe.__data__[certificate_offset : certificate_offset + certificate_size]

        #가져온 데이터를 바이너리로 출력
        hex_data = binascii.hexlify(certificate_data).decode('utf-8')
        print(f"CERTIFICATE Table data:\n{hex_data}")

        # CERTIFICATE 필드 정보 출력
        print("dwLength: ", swap_endianness(hex_data[0x0:0x8], 4))
        print("wRevision: ", swap_endianness(hex_data[0x8:0xc], 2))
        print("wCertificateType: ", swap_endianness(hex_data[0x0c:0x10], 2))
        #이후는 Certificate(인증서 데이터가 저장된 부분으로 가변 길이)
        
    else:
        print("CERTIFICATE Table이 존재하지 않습니다.")

def load_and_print_certificate_info(file_path):
    try:
        # PE 파일을 로드
        pe = pefile.PE(file_path)

        # CERTIFICATE 정보 출력
        print_certificate_info(pe)

    except Exception as e:
        print(f"PE 파일을 로드하는 중 오류 발생: {str(e)}")

if __name__ == "__main__":
    
    file_path = input("Enter the path of the PE file: ")   
    
    save_json_result()
     
    if not os.path.exists(file_path):
        print(f"Error: File not found - {file_path}")
        sys.exit(1)

    
    
    entropy_value = calculate_entropy(file_path)
    print("="* 100 + "\n")
    print(f"Entropy: {entropy_value}")
    check_if_dll_or_exe(file_path)
    print("="* 100)
    print_pe_header(file_path)
    print("="* 100)
    print_pe_section(file_path)
    print("="* 100)
    print_imports_and_exports(file_path) 
    print("="* 10)
    print_resource(file_path) 
    print("="* 100)
    print_relocation(file_path)
    print("="* 100)
    # print_strings(file_path) 
    print("="* 100)
    print_tls(file_path)
    print("="* 100)
    print_hash(file_path) 
    print("="* 100)
    find_exe_files(file_path)   
    print("="* 100)
    print_rich_header(file_path)
    print("="* 100)
    is_upx_packed(file_path)
    load_and_print_certificate_info(file_path)


