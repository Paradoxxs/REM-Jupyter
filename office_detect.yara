rule office_detect 
{
  strings: 
    $vbaProjectbin = "vbaProject.bin"
    $a = {d0 cf 11 e0}
    $b = {00 41 74 74 72 69 62 75 74 00}
  condition:
    uint32be(0) = 0x504b0304 and $vbaProjectbin or
    $a at 0 and $b
}
