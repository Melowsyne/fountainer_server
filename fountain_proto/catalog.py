# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Server-side datapoint catalog (excerpt from spec §5.2/§11.2).

The server knows type/access/limits for logging/plausibility. The authoritative,
atomic validation happens on the device (§7.11).
"""

# name -> (type, access, min, max)
CATALOG = {
    "Device_Serial_Number":    ("u64", "ro", None, None),
    "Device_HW_Version":       ("string", "ro", None, None),
    "Device_SW_Version":       ("string", "ro", None, None),
    "System_Temperature":      ("f32", "ro", None, None),
    "System_Utilization":      ("u8", "ro", None, None),
    "System_Memory_Free":      ("u32", "ro", None, None),
    "System_Flash_Free":       ("u32", "ro", None, None),
    "System_RSSI":             ("i8", "ro", None, None),
    "Fon_Current_Pressure":    ("f32", "ro", None, None),
    "Fon_Current_State":       ("enum", "ro", None, None),
    "Fon_Relay_Output":        ("bool", "ro", None, None),
    "Fon_Run_Time":            ("u32", "ro", None, None),
    "Fon_Cycles_Total":        ("u32", "ro", None, None),
    "Fon_Remaining_Time":      ("u32", "ro", None, None),
    "Fon_Min_Pressure":        ("f32", "rw", 0.0, 10.0),
    "Fon_Max_Pressure":        ("f32", "rw", 0.0, 10.0),
    "Fon_Alert_High_Pressure": ("f32", "rw", 0.0, 12.0),
    "Fon_Alert_Low_Pressure":  ("f32", "rw", 0.0, 10.0),
    "Fon_Min_On_Time":         ("u16", "rw", 0, 65535),
    "Fon_Max_On_Time":         ("u16", "rw", 10, 65535),
    "Fon_Dry_Run_Detect_Time": ("u16", "rw", 1, 3600),
    "Fon_Dry_Run_Min_Rise":    ("u16", "rw", 0, 10000),
    "Fon_Check_Valve_Timeout": ("u16", "rw", 1, 3600),
    "Fon_Pressure_Drop_Rate":  ("u16", "rw", 0, 65535),
    "Fon_Report_Interval":     ("u16", "rw", 1, 3600),
    "Fon_Sensor_Offset":       ("i16", "rw", -5000, 5000),
    "Fon_Sensor_Scale":        ("f32", "rw", None, None),
}

STATE_LABELS = {0: "Init", 1: "Off", 2: "On", 3: "Auto", 4: "Manual", 5: "Failure"}
