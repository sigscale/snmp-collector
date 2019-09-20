# [SigScale](http://www.sigscale.org) SNMP Collector

SigScale SNMP Collector is used by communications service providers
(CSP) to terminate the fault management (FM) north bound interfaces
(NBI) of various vendors' element management systems (EMS).

FM events are received as SNMP (v1, v2c, v3) TRAPs which are decoded
using installed MIBs and vendor plugin modules. Vendor specific NBIs
are normalized to the information model of ITU-T
[X.721](http://www.itu.int/itu-t/recommendations/rec.aspx?rec=3060)/
[X.733](http://www.itu.int/itu-t/recommendations/rec.aspx?rec=3071)
and 3GPP [32.111-2](http://webapp.etsi.org/key/key.asp?GSMSpecPart1=32&GSMSpecPart2=111&Search=search)
and adapted to the virtual event streaming (VES)
[API](http://wiki.onap.org/display/DW/VES+7.1) to be sent northbound.
The [DMaaP](http://wiki.onap.org/display/DW/Data+Movement+as+a+Platform+Project)
service of [ONAP](http://www.onap.org/)
[DCAE](https://wiki.onap.org/display/DW/Data+Collection+Analytics+and+Events+Project)
subsystem may be used to distribute fault events or they may be sent
directly to SigScale's VES Collector, part of our Fault Surveillance project.

### Graphical User Interface (GUI)
A web front end built with Google [Polymer](https://www.polymer-project.org)
web components for
[material design](https://material.io/guidelines/material-design/introduction.html)
provides event views and MIB management.

