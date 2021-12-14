rule pe_detect
{
    strings:
        $PE_magic_byte = "MZ"
    condition:
        $PE_magic_byte at 0
}