## Makefile.am
## vim: ts=3
##
## Process this file with automake to produce Makefile.in

appdir = $(beamdir)
app_DATA = snmp_collector.app
EXTRA_DIST = snmp_collector.app

beam_DATA = snmp_collector_app.beam \
			snmp_collector_sup.beam \
			snmp_collector_get_sup.beam \
			snmp_collector_server.beam \
			snmp_collector_event_sup.beam \
			snmp_collector_event_server.beam \
			snmp_collector_event_log.beam \
			snmp_collector_event_ves.beam \
			snmp_collector_get_fsm.beam \
			snmp_collector_trap_huawei_imap.beam \
			snmp_collector_trap_huawei_hw.beam \
			snmp_collector_trap_zte.beam \
			snmp_collector_trap_nokia.beam \
			snmp_collector_trap_nec.beam \
			snmp_collector_trap_hpe.beam \
			snmp_collector_trap_cisco.beam \
			snmp_collector_trap_emc.beam \
			snmp_collector_trap_huawei_servers.beam \
			snmp_collector_trap_rfc3877.beam \
			snmp_collector_trap_adva.beam \
			snmp_collector_trap_generic.beam \
			snmp_collector_debug_sup.beam \
			snmp_collector_debug_fsm.beam \
			snmp_collector.beam \
			snmp_collector_utils.beam \
			snmp_collector_log.beam \
			snmp_collector_snmp_usm.beam \
			snmp_collector_usm.beam \
			snmp_collector_mib.beam \
			snmp_collector_rest.beam \
			snmp_collector_snmpm_user_default.beam \
			snmp_collector_rest_accepted_content.beam \
			snmp_collector_rest_get.beam \
			snmp_collector_rest_post.beam \
			snmp_collector_rest_delete.beam \
			snmp_collector_rest_res_user.beam \
			snmp_collector_rest_res_mib.beam \
			snmp_collector_rest_res_counter.beam \
			snmp_collector_rest_res_event.beam \
			snmp_collector_rest_pagination_sup.beam \
			snmp_collector_rest_pagination_server.beam \
			snmp_collector_rest_res_http.beam \
			snmp_collector_rest_query_scanner.beam \
			snmp_collector_rest_query_parser.beam \
			snmp_collector_manager_fsm.beam \
			snmp_collector_manager_fsm_sup.beam \
			snmp_collector_manager_server.beam \
			snmp_collector_manager_sup_sup.beam \
			snmp_collector_manager_port_sup.beam \
			snmp_collector_manager_sup.beam

%.beam:$(top_srcdir)/src/%.erl	$(top_srcdir)/include/snmp_collector.hrl
	$(ERLC) $(ERLCFLAGS) -I $(top_srcdir)/include -I $(top_builddir)/include $<

snmp_collector_rest_query_scanner.beam:$(top_builddir)/src/snmp_collector_rest_query_scanner.erl
	$(ERLC) $<

snmp_collector_rest_query_parser.beam:$(top_builddir)/src/snmp_collector_rest_query_parser.erl
	$(ERLC) $<

%.app:   %.app-in
	sed -e 's/%APP_NAME%/$(PACKAGE_NAME)/' \
			-e 's/%APP_VERSION%/$(PACKAGE_VERSION)/' \
			-e 's#%APP_PRIV%#$(ERLANG_INSTALL_LIB_DIR)/$(PACKAGE_NAME)-$(PACKAGE_VERSION)/priv#' < $< > $@

CLEANFILES = $(beam_DATA) $(app_DATA)

