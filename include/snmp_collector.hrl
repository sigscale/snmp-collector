% snmp_collector.hrl

-record(snmp_user,
		{name :: string() | '_',
		authPass :: string() | '_',
		privPass :: string() | '_'}).
