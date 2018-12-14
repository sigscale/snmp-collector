% snmp_collector.hrl

-record(snmp_users,
		{name :: string() | '_',
		authPass :: string() | '_',
		privPass :: string() | '_'}).
