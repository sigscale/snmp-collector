## Makefile.am
## vim: ts=3
##
## Process this file with automake to produce Makefile.in

testmods = snmp_collector_snmp_SUITE

check_DATA = .dialyzer_ok .common_test_ok

.dialyzer_ok:	$(addsuffix .beam, $(testmods))
	dialyzer --src $(top_srcdir)/src

%.beam:$(top_srcdir)/test/%.erl $(top_srcdir)/include/snmp_collector.hrl
	$(ERLC) -pa $(top_builddir)/ebin $(ERLCFLAGS) -I $(top_srcdir)/include $<

snmp_collector_snmp_SUITE_data/%.bin:$(top_srcdir)/test/snmp_collector_snmp_SUITE_data/%.mib
	@if [ ! -d snmp_collector_snmp_SUITE_data ]; then mkdir snmp_collector_snmp_SUITE_data; fi
	$(ERLC) -o snmp_collector_snmp_SUITE_data $<

.common_test_ok:	$(addsuffix .beam, $(testmods)) snmp_collector_snmp_SUITE_data/CT-TRAP-MIB.bin
	@if [ ! -d log ]; then mkdir log; fi
	@if [ ! -f ct.cfg ]; then cp $(top_srcdir)/test/ct.cfg .; fi
	@if [ ! -f test.spec ]; then cp $(top_srcdir)/test/test.spec .; fi
	ct_run -no_auto_compile -pa $(top_builddir)/ebin -logdir log -config ct.cfg -spec test.spec -dir . -erl_args -noshell -sname $(LOGNAME)-ct

clean-local:
	-rm -r log/*

