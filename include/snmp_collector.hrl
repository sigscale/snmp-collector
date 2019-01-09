% snmp_collector.hrl

-record(snmp_user,
		{name :: string() | undefined | '_',
		authPass :: string() | undefined | '_',
		privPass :: string() | undefined | '_'}).
