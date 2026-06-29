rule Drone_Malware {
    strings:
        $s1 = "DRONE_TAKEOVER"
    condition:
        $s1
}