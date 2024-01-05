import hashlib
import pefile
import ordlookup

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

#imphash 함수 계산
def func_imphash(file_path):
    pe = pefile.PE(file_path)
    f_imphash = pe.get_imphash()
    return f_imphash

#imphash 자체 계산
def calc_imphash(file_path):
    pe = pefile.PE(file_path)
    
    impstrs = [] 
    exts = ["ocx", "sys", "dll"] 
        
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return "No DIRECTORY ENTRY IMPORT" 
        
    for entry in pe.DIRECTORY_ENTRY_IMPORT: 
        if isinstance(entry.dll, bytes):
            libname = entry.dll.decode().lower() 
        else:
            libname = entry.dll.lower()
                
        parts = libname.rsplit(".", 1) 
        if len(parts) > 1 and parts[1] in exts:
            libname = parts[0]

        entry_dll_lower = entry.dll.lower()
        for imp in entry.imports:
            funcname = None
            if not imp.name:
                funcname = ordlookup.ordLookup(
                    entry_dll_lower, imp.ordinal, make_name=True
                )
                if not funcname:
                    print(f"No Function name {entry.dll}:{imp.ordinal:04x}")
                        
            else:
                funcname = imp.name

            if not funcname: 
                continue

            if isinstance(funcname, bytes):
                funcname = funcname.decode()
            impstrs.append("%s.%s" % (libname.lower(), funcname.lower()))

        c_imphash =  hashlib.md5(",".join(impstrs).encode()).hexdigest()
        
        return c_imphash
            
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
