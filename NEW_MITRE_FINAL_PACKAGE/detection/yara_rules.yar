rule DroneFlood_Mutex {
    meta:
        description = "Detects DroneFlood mutex artifact"
        author = "SOC Analyst"
        date = "2026-06-30"
    strings:
        $mutex = "DF_MUTEX_01" ascii wide
        $mutex2 = "DRONEFLOOD_INSTANCE" ascii wide
    condition:
        $mutex or $mutex2
}

rule DroneFlood_C2_Domain {
    meta:
        description = "Detects hardcoded C2 domain in binary"
        author = "SOC Analyst"
        date = "2026-06-30"
    strings:
        $domain1 = "c2.dronefleet.net" ascii
        $domain2 = "api.dronefleet.net" ascii
    condition:
        $domain1 or $domain2
}

rule DroneFlood_Payload_Encoding {
    meta:
        description = "Detects XOR+Base64 obfuscation pattern"
        author = "SOC Analyst"
        date = "2026-06-30"
    strings:
        $xor_pattern = { 42 58 4F 52 2B 42 61 73 65 36 34 }  // "XOR+Base64"
        $base64_blob = /[A-Za-z0-9+/]{40,}={0,2}/
    condition:
        $xor_pattern or (#base64_blob > 3)
}

rule DroneFlood_Malicious_API {
    meta:
        description = "Detects malicious API calls (CreateMutex, InternetOpen)"
        author = "SOC Analyst"
        date = "2026-06-30"
    strings:
        $api1 = "CreateMutexA" ascii
        $api2 = "InternetOpenA" ascii
        $api3 = "WinHttpOpen" ascii
    condition:
        any of them
}

rule DroneFlood_Network_Command {
    meta:
        description = "Detects FLEET_COMMAND_PUSH string in network payload"
        author = "SOC Analyst"
        date = "2026-06-30"
    strings:
        $cmd1 = "FLEET_COMMAND_PUSH" ascii
        $cmd2 = "FLEET_SYNC" ascii
        $cmd3 = "gps_spoof" ascii
    condition:
        any of them
}