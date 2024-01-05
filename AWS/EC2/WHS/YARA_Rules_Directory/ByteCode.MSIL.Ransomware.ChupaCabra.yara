rule ByteCode_MSIL_Ransomware_ChupaCabra : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "CHUPACABRA"
        description         = "Yara rule that detects ChupaCabra ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "ChupaCabra"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 72 ?? ?? ?? ?? 73 ?? ?? ?? ?? 7A 7E ?? ?? ?? ?? 28
            ?? ?? ?? ?? 2C ?? 72 ?? ?? ?? ?? 73 ?? ?? ?? ?? 7A 14 0A 14 0B 7E ?? ?? ?? ?? 7E ?? ??
            ?? ?? 73 ?? ?? ?? ?? 0C 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 0D 09 73 ?? ?? ?? ?? 13 ?? 73 ??
            ?? ?? ?? 0A 06 08 06 6F ?? ?? ?? ?? 1E 5B 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 11 ?? 28 ??
            ?? ?? ?? 6F ?? ?? ?? ?? 06 06 6F ?? ?? ?? ?? 06 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 11
            ?? 11 ?? 16 73 ?? ?? ?? ?? 13 ?? 11 ?? 73 ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 0B DE
            ?? 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? DC 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? DC 11 ?? 2C ??
            11 ?? 6F ?? ?? ?? ?? DC 06 2C ?? 06 6F ?? ?? ?? ?? DC 07 2A
        }

        $encrypt_files_p2 = {
            02 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 20 ?? ?? ?? ?? 6A 30 ?? 02 28 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 0A 02 06 28 ?? ?? ?? ?? 02 02 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 38 ?? ??
            ?? ?? 02 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 20 ?? ?? ?? ?? 6A 30 ?? 20 ?? ?? ?? ?? 8D ?? ??
            ?? ?? 0B 02 19 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 0C 08 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ??
            ?? ?? ?? 0D 09 07 09 8E 69 28 ?? ?? ?? ?? DE ?? 08 2C ?? 08 6F ?? ?? ?? ?? DC 02 19 28
            ?? ?? ?? ?? 73 ?? ?? ?? ?? 13 ?? 11 ?? 07 6F ?? ?? ?? ?? DE ?? 11 ?? 2C ?? 11 ?? 6F ??
            ?? ?? ?? DC 02 02 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? DD ?? ?? ?? ?? 26 02 28
            ?? ?? ?? ?? 13 ?? 11 ?? 17 5F 17 33 ?? 11 ?? 17 28 ?? ?? ?? ?? 13 ?? 02 11 ?? 28 ?? ??
            ?? ?? 02 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 20 ?? ?? ?? ?? 6A 30 ?? 02 28 ?? ?? ?? ?? 28 ??
            ?? ?? ?? 13 ?? 02 11 ?? 28 ?? ?? ?? ?? 02 02 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 38 ?? ?? ?? ?? 02 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 20 ?? ?? ?? ?? 6A 30 ?? 20 ?? ?? ??
            ?? 8D ?? ?? ?? ?? 13 ?? 02 19 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 13 ?? 11 ?? 20 ?? ?? ?? ??
            6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? DE ?? 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? DC 02 19 28
            ?? ?? ?? ?? 73 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 6F ?? ?? ?? ?? DE ?? 11 ?? 2C ?? 11 ?? 6F
            ?? ?? ?? ?? DC 02 02 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? DE ?? DE ?? 26 DE ??
            2A
        }

        $find_files_p1 = {
            02 28 ?? ?? ?? ?? 0A 02 28 ?? ?? ?? ?? 0B 16 0C 2B ?? 06 08 9A 28 ?? ?? ?? ?? 72 ?? ??
            ?? ?? 6F ?? ?? ?? ?? 2D ?? 06 08 9A 28 ?? ?? ?? ?? 08 17 58 0C 08 06 8E 69 32 ?? 16 0D
            2B ?? 07 09 9A 28 ?? ?? ?? ?? 09 17 58 0D 09 07 8E 69 32 ?? DE ?? 26 DE ?? 2A
        }

        $find_files_p2 = {
            72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 3A ?? ?? ??
            ?? 1F ?? 8D ?? ?? ?? ?? 25 16 1E 28 ?? ?? ?? ?? A2 25 17 1F ?? 28 ?? ?? ?? ?? A2 25 18
            1F ?? 28 ?? ?? ?? ?? A2 25 19 1F ?? 28 ?? ?? ?? ?? A2 25 1A 1F ?? 28 ?? ?? ?? ?? A2 25
            1B 1B 28 ?? ?? ?? ?? A2 25 1C 1C 28 ?? ?? ?? ?? A2 25 1D 1F ?? 28 ?? ?? ?? ?? A2 25 1E
            1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 1F ?? 28 ?? ?? ?? ??
            A2 25 1F ?? 1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 1B 28 ??
            ?? ?? ?? A2 25 1F ?? 1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 1F ?? 28 ?? ?? ?? ?? A2 25 1F ??
            1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 1F ?? 28 ?? ?? ?? ??
            A2 0A 16 0B 2B ?? 06 07 9A 28 ?? ?? ?? ?? 07 17 58 0B 07 06 8E 69 32 ?? 2A
        }

        $drop_ransom_note = {
            7E ?? ?? ?? ?? 2C ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 39 ?? ?? ?? ?? 20 ?? ?? ?? ?? 28 ??
            ?? ?? ?? 28 ?? ?? ?? ?? 1F ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 1B 8D ?? ??
            ?? ?? 25 16 72 ?? ?? ?? ?? A2 25 17 7E ?? ?? ?? ?? A2 25 18 72 ?? ?? ?? ?? A2 25 19 7E
            ?? ?? ?? ?? A2 25 1A 72 ?? ?? ?? ?? A2 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 20
            ?? ?? ?? ?? 28 ?? ?? ?? ?? 1B 8D ?? ?? ?? ?? 25 16 72 ?? ?? ?? ?? A2 25 17 7E ?? ?? ??
            ?? A2 25 18 72 ?? ?? ?? ?? A2 25 19 7E ?? ?? ?? ?? A2 25 1A 72 ?? ?? ?? ?? A2 28 ?? ??
            ?? ?? 28 ?? ?? ?? ?? 26 1F ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 26 73 ?? ?? ?? ?? 0A 7E ?? ?? ?? ?? 0B 06 07 6F ?? ?? ?? ?? 26 2A
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_p*)
        ) and
        (
            all of ($encrypt_files_p*)
        ) and
        (
            $drop_ransom_note
        )
}