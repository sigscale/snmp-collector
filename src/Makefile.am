## Makefile.am
## vim: ts=3
##
## Process this file with automake to produce Makefile.in

erl_DATA = snmp_collector_rest_query_scanner.erl \
		snmp_collector_rest_query_parser.erl

%.erl:%.xrl
	$(ERLC) $<

%.erl:%.yrl
	$(ERLC) $<

CLEANFILES = $(erl_DATA)

