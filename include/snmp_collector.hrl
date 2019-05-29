% snmp_collector.hrl

-record(snmp_user,
		{name :: string() | undefined | '_',
		authPass :: string() | undefined | '_',
		privPass :: string() | undefined | '_'}).

% Event Types [ITU-T X.733].

-define(?ET_Operational_Violation, "Operational Violation").
-define(?ET_Power_System, "Power System").
-define(?ET_Environmental_Alarm, "Environmental Alarm").
-define(?ET_Signaling_System, "Signaling System").
-define(?ET_Trunk_System, "Trunk System").
-define(?ET_Hardware_System, "Hardware System").
-define(?ET_Software_System, "Software System").
-define(?ET_Running_System, "Running System").
-define(?ET_Communication_System, "Communication System").
-define(?ET_Quality_Of_Service_Alarm, "Quality Of ServiceAlarm").
-define(?ET_Processing_Error, "Processing Error").
-define(?ET_OMC, "OMC").
-define(?ET_Integrity_Violation, "Integrity Violation").
-define(?ET_Operational_Violation, "Operational Violation").
-define(?ET_Physical_Violation, "Physical Violation").
-define(?ET_Security_Service_Or_Mechanism_Violation, "Security Service Or Mechanism Violation").
-define(?ET_Time_Domain_Violation, "Time Domain Violation").
