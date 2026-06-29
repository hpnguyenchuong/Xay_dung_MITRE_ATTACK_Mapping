rule DroneFlood_YARA {
    strings:
        $s = "DF_MUTEX_01"
    condition:
        $s
}