## Makefile.am
## vim: ts=3
##
## Process this file with automake to produce Makefile.in

CERT_DIR = certificates

testmods = snmp_collector_snmp_SUITE \
		snmp_collector_api_SUITE \
		snmp_collector_rest_SUITE

check_DATA = .dialyzer_ok .common_test_ok

.dialyzer_ok:	$(addsuffix .beam, $(testmods))
	dialyzer --src $(top_srcdir)/src

%.beam:$(top_srcdir)/test/%.erl $(top_srcdir)/include/snmp_collector.hrl
	$(ERLC) -pa $(top_builddir)/ebin $(ERLCFLAGS) -I $(top_srcdir)/include $<

snmp_collector_snmp_SUITE_data/%.bin:$(top_srcdir)/test/snmp_collector_snmp_SUITE_data/%.mib
	@if [ ! -d snmp_collector_snmp_SUITE_data ]; then mkdir snmp_collector_snmp_SUITE_data; fi
	$(ERLC) -o snmp_collector_snmp_SUITE_data $<

.common_test_ok:	$(addsuffix .beam, $(testmods)) snmp_collector_snmp_SUITE_data/CT-TRAP-MIB.bin sys.config
	@if [ ! -d log ]; then mkdir log; fi 
	@if [ ! -f ct.cfg ]; then cp $(top_srcdir)/test/ct.cfg .; fi
	@if [ ! -f test.spec ]; then cp $(top_srcdir)/test/test.spec .; fi
	(cd $(CERT_DIR) && \
		if [ ! -f CAkey.pem -o ! -f CAcert.pem ]; then \
			openssl req -newkey rsa:2048 -nodes -x509 -days 30 \
					-subj /C=CA/ST=Ontario/L=Toronto/O=Example/CN=$(hostname)\/emailAddress=support@$(hostname) \
					-keyout CAkey.pem -out CAcert.pem; \
		fi; \
		if [ ! -f key.pem -o ! -f cert.csr ]; then \
		openssl req -newkey rsa:2048 -nodes \
				-subj /C=CA/ST=Ontario/L=Toronto/O=Example/CN=$(hostname)\/emailAddress=support@$(hostname) \
				-keyout key.pem -out cert.csr; \
		fi; \
		if [ ! -f extensions ]; then \
			echo "extendedKeyUsage = serverAuth" > extensions; \
			echo "subjectAltName = DNS:$$(hostname)" >> extensions; \
		fi; \
		if [ ! -f cert.pem ]; then \
			openssl x509 -req -CA CAcert.pem -CAkey CAkey.pem -CAcreateserial \
					-extfile extensions -in cert.csr -out cert.pem; \
		fi)
	ct_run -no_auto_compile -pa $(top_builddir)/ebin -logdir log -config ct.cfg -spec test.spec -dir . -erl_args -noshell -sname $(LOGNAME)-ct -config sys

sys.config:	$(top_srcdir)/test/sys.config-in
	sed -e 's#%CERT_DIR%#$(abs_top_builddir)/test/$(CERT_DIR)#' \
			-e 's#%APP_PRIV%#$(abs_top_srcdir)/priv#' \
			-e 's#%SERVER_ROOT%#$(abs_top_builddir)/test#' \
			-e "s#%HTTP_PORT%#$$(($$RANDOM + 32768))#" < $< > $@

clean-local:
	-rm -r *.beam certificates/* log/*

