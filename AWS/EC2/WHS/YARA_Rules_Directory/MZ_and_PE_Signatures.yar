rule MZ_and_PE_Signatures {
    strings:
        $mz_signature = "MZ"
        $pe_signature = "PE"

    condition:
        $mz_signature at 0 and $pe_signature at 0x3C
}

