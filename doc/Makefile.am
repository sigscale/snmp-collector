## Makefile.am
## vim: ts=3
##
## Process this file with automake to produce Makefile.in

modhtml = snmp_collector_app.html \
			snmp_collector_sup.html \
			snmp_collector_get_sup.html \
			snmp_collector_server.html \
			snmp_collector_event_sup.html \
			snmp_collector_event_server.html \
			snmp_collector_event_log.html \
			snmp_collector_event_ves.html \
			snmp_collector_get_fsm.html \
			snmp_collector_trap_huawei_imap.html \
			snmp_collector_trap_huawei_hw.html \
			snmp_collector_trap_nokia.html \
			snmp_collector_trap_zte.html \
			snmp_collector_trap_nec.html \
			snmp_collector_trap_hpe.html \
			snmp_collector_trap_cisco.html \
			snmp_collector_trap_emc.html \
			snmp_collector_trap_huawei_servers.html \
			snmp_collector_trap_rfc3877.html \
			snmp_collector_trap_adva.html \
			snmp_collector_trap_generic.html \
			snmp_collector_debug_sup.html \
			snmp_collector_debug_fsm.html \
			snmp_collector.html \
			snmp_collector_utils.html \
			snmp_collector_log.html \
			snmp_collector_snmp_usm.html \
			snmp_collector_usm.html \
			snmp_collector_mib.html \
			snmp_collector_snmpm_user_default.html \
			snmp_collector_rest_accepted_content.html \
			snmp_collector_rest_get.html \
			snmp_collector_rest_post.html \
			snmp_collector_rest_delete.html \
			snmp_collector_rest_res_user.html \
			snmp_collector_rest_res_mib.html \
			snmp_collector_rest_res_counter.html \
			snmp_collector_rest_res_event.html \
			snmp_collector_rest_pagination_sup.html \
			snmp_collector_rest_pagination_server.html \
			snmp_collector_rest_res_http.html \
			snmp_collector_rest_query_scanner.html \
			snmp_collector_rest_query_parser.html \
			snmp_collector_manager_fsm.html \
			snmp_collector_manager_fsm_sup.html \
			snmp_collector_manager_server.html \
			snmp_collector_manager_sup_sup.html \
			snmp_collector_manager_port_sup.html \
			snmp_collector_manager_sup.html

doc_DATA = overview.edoc $(modhtml) \
		modules-frame.html overview-summary.html \
		index.html stylesheet.css \
		sigscale-logo.png supervision.png

overview.edoc: overview.edoc-in
	sed -e 's!%VERSION%!$(VERSION)!' \
			-e 's!%DESCRIPTION%!$(PACKAGE)!' < $< > $@

%.html:$(top_srcdir)/src/%.erl	overview.edoc $(top_srcdir)/doc/supervision.edoc
	$(ERL) -noshell -run edoc_run application \
			"'$(PACKAGE_NAME)'" "'$(top_builddir)'" \
			'[{sort_functions,false},{private,true},{todo,true},{source_path,["$(top_srcdir)/src"]},{subpackages,false},{def,{docsrc,"$(top_srcdir)/doc/{@?}"}},{stylesheet_file, "$(top_srcdir)/doc/sigscale.css"}]'
	for i in `ls *.html`; do \
			sed -e 's!erlang logo!sigscale logo!' \
					-e 's!href=\"http://www.erlang.org/\"!href=\"http://www.sigscale.org/\"!' \
					-e 's!erlang.png!sigscale-logo.png!' $$i > $$i.tmp; \
			mv $$i.tmp $$i; \
	done
	-cp -n $(top_srcdir)/doc/sigscale-logo.png .
	-cp -n $(top_srcdir)/doc/supervision.png .

CLEANFILES = overview.edoc edoc-info index.html \
		modules-frame.html overview-summary.html packages-frame.html \
		stylesheet.css erlang.png $(modhtml)

