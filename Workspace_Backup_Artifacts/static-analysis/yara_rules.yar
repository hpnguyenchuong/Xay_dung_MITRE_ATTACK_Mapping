rule DroneFlood_Mutex {
    meta:
        description = "Detects DroneFlood Mutex artifact"
    strings:
        $mutex = "DF_MUTEX_01"
    condition:
        $mutex
}