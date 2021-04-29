/**
 * @license
 * Copyright (c) 2020 The Polymer Project Authors. All rights reserved.
 * This code may only be used under the BSD style license found at http://polymer.github.io/LICENSE.txt
 * The complete set of authors may be found at http://polymer.github.io/AUTHORS.txt
 * The complete set of contributors may be found at http://polymer.github.io/CONTRIBUTORS.txt
 * Code distributed by Google as part of the polymer project is also
 * subject to an additional IP rights grant found at http://polymer.github.io/PATENTS.txt
 */

import { PolymerElement, html } from '@polymer/polymer/polymer-element.js';
import { select, selectAll } from 'd3-selection';
import { arc, pie, stack } from 'd3-shape';
import { scaleOrdinal, scaleBand, scaleLinear, scaleQuantize } from 'd3-scale';
import { axisBottom, axisLeft } from 'd3-axis';
import { max, descending } from 'd3-array';
import "@polymer/paper-card/paper-card.js";
import '@polymer/paper-dropdown-menu/paper-dropdown-menu.js';
import '@polymer/paper-listbox/paper-listbox.js';
import "@polymer/paper-item/paper-icon-item.js";
import '@polymer/iron-ajax/iron-ajax.js';
import './style-element.js';

class vendorBoard extends PolymerElement {
	static get template() {
		return html`
			<style include="style-element">
			</style>
			<paper-card>
				<paper-dropdown-menu label="Event Type" no-animations="true">
					<paper-listbox id="vendorSelect" slot="dropdown-content" selected="2">
						<paper-item>Huawei</paper-item>
						<paper-item>ZTE</paper-item>
						<paper-item>Nokia</paper-item>
						<paper-item>Rfc3877</paper-item>
					</paper-listbox>
				</paper-dropdown-menu>
				<div class="card-content">
					<svg id="vendorEvent" width="700" height="300"></svg>
				</div>
			</paper-card>
			<paper-card>
				<paper-dropdown-menu label="Severity" no-animations="true">
					<paper-listbox id="severeSelect" slot="dropdown-content" selected="2">
						<paper-item>Huawei</paper-item>
						<paper-item>ZTE</paper-item>
						<paper-item>Nokia</paper-item>
						<paper-item>Rfc3877</paper-item>
					</paper-listbox>
				</paper-dropdown-menu>
				<div class="card-content">
					<svg id="vendorSeverity" width="700" height="300"></svg>
				</div>
			</paper-card>
			<paper-card heading="Agent">
				<div class="card-content">
					<svg id="agent" width="500" height="260"></svg>
				</div>
			</paper-card>
			<paper-card heading="Total">
				<div class="card-content">
					<svg id="total" width="500" height="260"></svg>
				</div>
			</paper-card>
			<iron-ajax
				id="getDashAjax"
				url="/counters/v1/snmp"
				rejectWithRequest>
			</iron-ajax>
		`;
	}

	static get properties() {
		return {
			loading: {
				type: Boolean,
				notify: true,
				value: false
			},
			history: {
				type: Array,
				readOnly: true,
				notify: false,
				value: function() {
					return []
				}
			}
		}
	}

	ready() {
		super.ready();
		this._load();
	}

	_load() {
		var ajax = document.body.querySelector('snmp-collector').shadowRoot.getElementById('vendorList').shadowRoot.getElementById('getDashAjax');
		var handleAjaxResponse = function(request) {
			if (request) {
				var dataArray = new Array();
				var req = request.response;
				var arr = new Array();
				if(request.response.vendor.huawei.total) {
					var HuTotVen = request.response.vendor.huawei.total;
					if(HuTotVen != undefined) {
						arr.push(HuTotVen);
					}
				}
				if(request.response.vendor.nokia.total) {
					var NoTotVen = request.response.vendor.nokia.total;
					if(NoTotVen != undefined) {
						arr.push(NoTotVen);
					}
				}
				if(request.response.vendor.zte.total) {
					var ZtTotVen = request.response.vendor.zte.total;
					if(ZtTotVen != undefined) {
						arr.push(ZtTotVen);
					}
				}
				if(request.response.vendor.rfc3877.total) {
					var RfcTotVen = request.response.vendor.rfc3877.total;
					if(RfcTotVen != undefined) {
						arr.push(RfcTotVen);
					}
				}
				var sum = arr.reduce(function(a, b){
					return a + b;
				}, 0);
				var totSystem = {"name": "total", "count": sum};
				var history = document.body.querySelector('snmp-collector').shadowRoot.getElementById('vendorList').history;
				var root1 = document.body.querySelector('snmp-collector').shadowRoot.getElementById('vendorList').shadowRoot;
				var color1 = scaleOrdinal(["#ff1744"]);
				var svg1 = select(root1).select("#total");
				draw_bar(svg1, [totSystem], color1);

				function draw_bar(svg, data, color) {
					svg.selectAll("*").remove();
					var width = +svg.attr('width'),
						height = +svg.attr('height'),
					g = svg.append("g").attr("transform", "translate(" + width / 2 + "," + height / 2 + ")");
					history.push(data);
					var historyI = history.map(addIndex);
					var margin = ({top: 20, right: 0, bottom: 30, left: 40});
					var x = scaleBand()
						.domain(historyI.map(d => d[0].index))
						.range([margin.left, width - margin.right])
						.padding(0.1);
					var y = scaleLinear()
						.domain([0, max(data, d => d.count)]).nice()
						.range([height - margin.bottom, margin.top]);
					var xAxis = g => g
						.attr("transform", `translate(0,${height - margin.bottom})`)
						.call(axisBottom(x).tickValues([]));
					var yAxis = g => g
						.attr("transform", `translate(${margin.left},0)`)
						.call(axisLeft(y))
						.call(g => g.select(".domain").remove());
					svg.append("g")
						.selectAll("g")
						.data(historyI)
						.enter().append("g")
						.selectAll("rect")
						.data(d => d.sort((x, y) => descending(x.count, y.count)))
						.enter().append("rect")
						.attr("fill", d => color(d.severity))
						.attr("x", d => x(d.index)).attr("y", d => y(d.count))
						.attr("y", d => y(d.count))
						.attr("height", d => y(0) - y(d.count))
						.attr("width", 30);
					svg.append("g").call(xAxis);
					svg.append("g").call(yAxis);
				}
				function addIndex(h, i) {
					h.map(function(d){
						return d.index = i;
					})
					return h;
				};

				var sysEventType = document.body.querySelector('snmp-collector')
							.shadowRoot.getElementById('vendorList');
				var newRecord2 = new Object();
				var req = request.response;
console.log(req);
				if(req) {
					for(var index in req.vendor.huawei.agent) {
						if(req.vendor.huawei.agent != "") {
							var HuaObjVen = req.vendor.huawei.agent[index];
							if(HuaObjVen.total != undefined) {
								newRecord2.huawei = HuaObjVen.total;
							}
						}
					}
					for(var index in req.vendor.nokia.agent) {
						if(req.vendor.nokia.agent != "") {
							var NokObjVen = req.vendor.nokia.agent[index];
							if(NokObjVen.total != undefined) {
								newRecord2.nokia = NokObjVen.total;
							}
						}
					}
					for(var index in req.vendor.zte.agent) {
						if(req.vendor.zte.agent != "") {
							var ZteObjVen = req.vendor.zte.agent[index];
							if(ZteObjVen.total != undefined) {
								newRecord2.zte = ZteObjVen.total;
							}
						}
					}
					for(var index in req.vendor.rfc3877.agent) {
						if(req.vendor.rfc3877.agent != "") {
							var RfcObjVen = req.vendor.rfc3877.agent[index];
							if(RfcObjVen.total != undefined) {
								newRecord2.rfc3877 = RfcObjVen.total;
							}
						}
					}
					var dataVen = newRecord2;
					var dataAgent = Object.keys(dataVen).map(k =>
								({ name: k, count: dataVen[k] }));
				}
				var root = document.body.querySelector('snmp-collector')
							.shadowRoot.getElementById('vendorList').shadowRoot;
				var color2 = scaleOrdinal(["#ff1744", "#ff9100", "#ffea00"]);
				var svg2 = select(root).select("#agent");
				sysEventType.draw_pie(svg2, dataAgent, color2);

				var selectedVenEve = sysEventType.shadowRoot
							.getElementById('vendorSelect').selected;
				var newRecord1 = new Object();
				if(selectedVenEve == 0) {
					if(req.vendor.huawei.eventType.communicationsAlarm != 0) {
						newRecord1.communicationsAlarm = req.vendor.huawei
									.eventType.communicationsAlarm;
					}
					if(req.vendor.huawei.eventType.environmentalAlarm != 0) {
						newRecord1.environmentalAlarm = req.vendor.huawei
									.eventType.environmentalAlarm;
					}
					if(req.vendor.huawei.eventType.equipmentAlarm != 0) {
						newRecord1.equipmentAlarm = req.vendor.huawei
									.eventType.equipmentAlarm;
					}
					if(req.vendor.huawei.eventType.integrityViolation != 0) {
						newRecord1.integrityViolation = req.vendor.huawei
									.eventType.integrityViolation;
					}
					if(req.vendor.huawei.eventType.operationalViolation != 0) {
						newRecord1.operationalViolation = req.vendor.huawei
									.eventType.operationalViolation;
					}
					if(req.vendor.huawei.eventType.physicalViolation != 0) {
						newRecord1.physicalViolation = req.vendor.huawei
									.eventType.physicalViolation;
					}
					if(req.vendor.huawei.eventType.processingErrorAlarm != 0) {
						newRecord1.processingErrorAlarm = req.vendor.huawei
									.eventType.processingErrorAlarm;
					}
					if(req.vendor.huawei.eventType.qualityofServiceAlarm != 0) {
						newRecord1.qualityofServiceAlarm = req.vendor.huawei
									.eventType.qualityofServiceAlarm;
					}
					if(req.vendor.huawei.eventType.securityServiceOrMechanismViolation != 0) {
						newRecord1.securityServiceOrMechanismViolation = req.vendor.huawei
									.eventType.securityServiceOrMechanismViolation;
					}
					if(req.vendor.huawei.eventType.timeDomainViolation != 0) {
						newRecord1.timeDomainViolation = req.vendor.huawei
									.eventType.timeDomainViolation;
					}
					var dataType = newRecord1;
					var dataEventType = Object.keys(dataType).map(k => ({ name: k, count: dataType[k] }));
				}
				if(selectedVenEve == 1) {
					if(req.vendor.zte.eventType.communicationsAlarm != 0) {
						newRecord1.communicationsAlarm = req.vendor.zte
									.eventType.communicationsAlarm;
					}
					if(req.vendor.zte.eventType.environmentalAlarm != 0) {
						newRecord1.environmentalAlarm = req.vendor.zte
									.eventType.environmentalAlarm;
					}
					if(req.vendor.zte.eventType.equipmentAlarm != 0) {
						newRecord1.equipmentAlarm = req.vendor.zte
									.eventType.equipmentAlarm;
					}
					if(req.vendor.zte.eventType.integrityViolation != 0) {
						newRecord1.integrityViolation = req.vendor.zte
									.eventType.integrityViolation;
					}
					if(req.vendor.zte.eventType.operationalViolation != 0) {
						newRecord1.operationalViolation = req.vendor.zte
									.eventType.operationalViolation;
					}
					if(req.vendor.zte.eventType.physicalViolation != 0) {
						newRecord1.physicalViolation = req.vendor.zte
									.eventType.physicalViolation;
					}
					if(req.vendor.zte.eventType.processingErrorAlarm != 0) {
						newRecord1.processingErrorAlarm = req.vendor.zte
									.eventType.processingErrorAlarm;
					}
					if(req.vendor.zte.eventType.qualityofServiceAlarm != 0) {
						newRecord1.qualityofServiceAlarm = req.vendor.zte
									.eventType.qualityofServiceAlarm;
					}
					if(req.vendor.zte.eventType.securityServiceOrMechanismViolation != 0) {
						newRecord1.securityServiceOrMechanismViolation = req.vendor.zte
									.eventType.securityServiceOrMechanismViolation;
					}
					if(req.vendor.zte.eventType.timeDomainViolation != 0) {
						newRecord1.timeDomainViolation = req.vendor.zte
									.eventType.timeDomainViolation;
					}
					var dataType = newRecord1;
					var dataEventType = Object.keys(dataType).map(k => ({ name: k, count: dataType[k] }));
				}
				if(selectedVenEve == 2) {
					if(req.vendor.nokia.eventType.communicationsAlarm != 0) {
						newRecord1.communicationsAlarm = req.vendor.nokia
									.eventType.communicationsAlarm;
					}
					if(req.vendor.nokia.eventType.environmentalAlarm != 0) {
						newRecord1.environmentalAlarm = req.vendor.nokia
									.eventType.environmentalAlarm;
					}
					if(req.vendor.nokia.eventType.equipmentAlarm != 0) {
						newRecord1.equipmentAlarm = req.vendor.nokia
									.eventType.equipmentAlarm;
					}
					if(req.vendor.nokia.eventType.integrityViolation != 0) {
						newRecord1.integrityViolation = req.vendor.nokia
									.eventType.integrityViolation;
					}
					if(req.vendor.nokia.eventType.operationalViolation != 0) {
						newRecord1.operationalViolation = req.vendor.nokia
									.eventType.operationalViolation;
					}
					if(req.vendor.nokia.eventType.physicalViolation != 0) {
						newRecord1.physicalViolation = req.vendor.nokia
									.eventType.physicalViolation;
					}
					if(req.vendor.nokia.eventType.processingErrorAlarm != 0) {
						newRecord1.processingErrorAlarm = req.vendor.nokia
									.eventType.processingErrorAlarm;
					}
					if(req.vendor.nokia.eventType.qualityofServiceAlarm != 0) {
						newRecord1.qualityofServiceAlarm = req.vendor.nokia
									.eventType.qualityofServiceAlarm;
					}
					if(req.vendor.nokia.eventType.securityServiceOrMechanismViolation != 0) {
						newRecord1.securityServiceOrMechanismViolation = req.vendor.nokia
									.eventType.securityServiceOrMechanismViolation;
					}
					if(req.vendor.nokia.eventType.timeDomainViolation != 0) {
						newRecord1.timeDomainViolation = req.vendor.nokia
									.eventType.timeDomainViolation;
					}
					var dataType = newRecord1;
					var dataEventType = Object.keys(dataType).map(k => ({name: k, count: dataType[k] }));
				}
				if(selectedVenEve == 3) {
					if(req.vendor.rfc3877.eventType.communicationsAlarm != 0) {
						newRecord1.communicationsAlarm = req.vendor.rfc3877
									.eventType.communicationsAlarm;
					}
					if(req.vendor.rfc3877.eventType.environmentalAlarm != 0) {
						newRecord1.environmentalAlarm = req.vendor.rfc3877
									.eventType.environmentalAlarm;
					}
					if(req.vendor.rfc3877.eventType.equipmentAlarm != 0) {
						newRecord1.equipmentAlarm = req.vendor.rfc3877
									.eventType.equipmentAlarm;
					}
					if(req.vendor.rfc3877.eventType.integrityViolation != 0) {
						newRecord1.integrityViolation = req.vendor.rfc3877
									.eventType.integrityViolation;
					}
					if(req.vendor.rfc3877.eventType.operationalViolation != 0) {
						newRecord1.operationalViolation = req.vendor.rfc3877
									.eventType.operationalViolation;
					}
					if(req.vendor.rfc3877.eventType.physicalViolation != 0) {
						newRecord1.physicalViolation = req.vendor.rfc3877
									.eventType.physicalViolation;
					}
					if(req.vendor.rfc3877.eventType.processingErrorAlarm != 0) {
						newRecord1.processingErrorAlarm = req.vendor.rfc3877
									.eventType.processingErrorAlarm;
					}
					if(req.vendor.rfc3877.eventType.qualityofServiceAlarm != 0) {
						newRecord1.qualityofServiceAlarm = req.vendor.rfc3877
									.eventType.qualityofServiceAlarm;
					}
					if(req.vendor.rfc3877.eventType.securityServiceOrMechanismViolation != 0) {
						newRecord1.securityServiceOrMechanismViolation = req.vendor.rfc3877
									.eventType.securityServiceOrMechanismViolation;
					}
					if(req.vendor.rfc3877.eventType.timeDomainViolation != 0) {
						newRecord1.timeDomainViolation = req.vendor.rfc3877
									.eventType.timeDomainViolation;
					}
					var dataType = newRecord1;
					var dataEventType = Object.keys(dataType).map(k => ({name: k, count: dataType[k] }));
				}
				var root = document.body.querySelector('snmp-collector')
							.shadowRoot.getElementById('vendorList').shadowRoot;
				var color = scaleOrdinal(["#ff1744", "#ff9100", "#ffea00","#00b0ff",
							"#33DCFF", "#33B2FF", "#FF33F7", "#FF338F", "#793030", "#2CF3FF"]);
				var svg = select(root).select("#vendorEvent");
				sysEventType.draw_pie(svg, dataEventType, color);

				var selectedVen = sysEventType.shadowRoot
							.getElementById('severeSelect').selected;
				var newRecord = new Object();
				if(selectedVen == 0) {
					if(req.vendor.huawei.perceivedSeverity.major != 0) {
						if(req.vendor.huawei.perceivedSeverity.major) {
							newRecord.major = req.vendor.huawei.perceivedSeverity.major;
						}
					}
					if(req.vendor.huawei.perceivedSeverity.minor != 0) {
						if(req.vendor.huawei.perceivedSeverity.minor) {
							newRecord.minor = req.vendor.huawei.perceivedSeverity.minor;
						}
					}
					if(req.vendor.huawei.perceivedSeverity.critical != 0) {
						if(req.vendor.huawei.perceivedSeverity.critical) {
							newRecord.critical = req.vendor.huawei.perceivedSeverity.critical;
						}
					}
					var dataHuw = newRecord;
					var dataEventType = Object.keys(dataHuw)
							.map(k => ({ name: k, count: dataHuw[k]}));
				}
				if(selectedVen == 1) {
					if(req.vendor.zte.perceivedSeverity.major != 0) {
						if(req.vendor.zte.perceivedSeverity.major) {
							newRecord.major = req.vendor.zte.perceivedSeverity.major;
						}
					}
					if(req.vendor.zte.perceivedSeverity.minor != 0) {
						if(req.vendor.zte.perceivedSeverity.minor) {
							newRecord.minor = req.vendor.zte.perceivedSeverity.minor;
						}
					}
					if(req.vendor.zte.perceivedSeverity.critical != 0) {
						if(req.vendor.zte.perceivedSeverity.critical) {
							newRecord.critical = req.vendor.zte.perceivedSeverity.critical;
						}
					}
					var dataZte = newRecord;
					var dataEventType = Object.keys(dataZte)
								.map(k => ({ name: k, count: dataZte[k]}));
				}
				if(selectedVen == 2) {
					if(req.vendor.nokia.perceivedSeverity.major != 0) {
						if(req.vendor.nokia.perceivedSeverity.major) {
							newRecord.major = req.vendor.nokia.perceivedSeverity.major;
						}
					}
					if(req.vendor.nokia.perceivedSeverity.minor != 0) {
						if(req.vendor.nokia.perceivedSeverity.minor) {
							newRecord.minor = req.vendor.nokia.perceivedSeverity.minor;
						}
					}
					if(req.vendor.nokia.perceivedSeverity.critical != 0) {
						if(req.vendor.nokia.perceivedSeverity.critical) {
							newRecord.critical = req.vendor.nokia.perceivedSeverity.critical;
						}
					}
					var dataNok = newRecord;
					var dataEventType = Object.keys(dataNok)
								.map(k => ({ name: k, count: dataNok[k]}));
				}
				if(selectedVen == 3) {
					if(req.vendor.rfc3877.perceivedSeverity.major != 0) {
						if(req.vendor.rfc3877.perceivedSeverity.major) {
							newRecord.major = req.vendor.rfc3877.perceivedSeverity.major;
						}
					}
					if(req.vendor.rfc3877.perceivedSeverity.minor != 0) {
						if(req.vendor.rfc3877.perceivedSeverity.minor) {
							newRecord.minor = req.vendor.rfc3877.perceivedSeverity.minor;
						}
					}
					if(req.vendor.rfc3877.perceivedSeverity.critical != 0) {
						if(req.vendor.rfc3877.perceivedSeverity.critical) {
							newRecord.critical = req.vendor.rfc3877.perceivedSeverity.critical;
						}
					}
					var dataRfc = newRecord;
					var dataEventType = Object.keys(dataRfc)
								.map(k => ({ name: k, count: dataRfc[k]}));
				}
				var root = document.body.querySelector('snmp-collector')
							.shadowRoot.getElementById('vendorList').shadowRoot;
				var color = scaleOrdinal(["#ff1744", "#ff9100", "#ffea00", "#00b0ff"]);
				var svg1 = select(root).select("#vendorSeverity");
				sysEventType.draw_pie(svg1, dataEventType, color);
			}
		}
		var handleAjaxError = function(error) {
			var toast = document.body.querySelector('snmp-collector').shadowRoot.getElementById('restError');
			toast.text = error;
			toast.open();
			callback([]);
		}
		if(ajax.loading) {
			ajax.lastRequest.completes.then(function(request) {
				return ajax.generateRequest().completes;
			}, handleAjaxError).then(handleAjaxResponse, handleAjaxError);
		} else {
			ajax.generateRequest().completes.then(handleAjaxResponse, handleAjaxError);
		}
	}

	draw_pie(svg, data, color) {
		svg.selectAll("*").remove();
		var g = svg.append("g");
		g.append("g")
			.attr("class", "labels");
		g.append("g")
			.attr("class", "lines");
		g.append("g")
			.attr("class", "slices");
		var width = +svg.attr('width');
		var height = +svg.attr('height');
		var radius = Math.min(width, height) / 2;
		var pie1 = pie()
			.sort(null)
			.value(function(d) {
				return d.count;
			});
		var path = arc()
			.outerRadius(radius*0.4)
			.innerRadius(radius*0.8);
		var label = arc()
			.outerRadius(radius * 0.9)
			.innerRadius(radius * 0.9);
		g.attr("transform", "translate(" + width / 2 + "," + height / 2 + ")");
		g.select('.slices').selectAll('path')
			.data(pie1(data))
			.enter().append('path')
			.attr('d', path)
			.attr("fill", function(d) {
				return color(d.data.name)
			});
		g.select('.lines').selectAll('polyline')
			.data(pie1(data))
			.enter().append('polyline')
			.attr('points', function(d) {
				var pos = label.centroid(d);
				pos[0] = radius * 0.95 * (midAngle(d) < Math.PI ? 1 : -1);
				return [path.centroid(d), label.centroid(d), pos]
			});
		g.select('.labels').selectAll('text')
			.data(pie1(data))
			.enter().append('text')
			.attr('dy', '.35em')
			.attr('dx', function(d) {
				return (midAngle(d)) < Math.PI ? '0.35em' : '-0.35em';
			})
			.html(function(d) {
				return d.data.name;
			})
			.attr('transform', function(d) {
				var pos = label.centroid(d);
				pos[0] = radius * 0.95 * (midAngle(d) < Math.PI ? 1 : -1);
				return 'translate(' + pos + ')';
			})
			.style('text-anchor', function(d) {
				return (midAngle(d)) < Math.PI ? 'start' : 'end';
			});
		function midAngle(d) {
			return d.startAngle + (d.endAngle - d.startAngle) / 2;
		};
	}
}

window.customElements.define('snmp-vendorboard', vendorBoard);
