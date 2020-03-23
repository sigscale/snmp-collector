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

class agentBoard extends PolymerElement {
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
		var ajax = document.body.querySelector('snmp-collector').shadowRoot
					.getElementById('agentList').shadowRoot.getElementById('getDashAjax');
		var handleAjaxResponse = function(request) {
			if (request) {
				var dataArray = new Array();
				var req = request.response;
				for(var index in req.vendor.huawei.agent) {
					if(request.response.vendor.huawei.agent != "") {
						var huwObj = request.response.vendor.huawei.agent[index];
						var huwTotal = huwObj.total;
					}
					if(request.response.vendor.nokia.agent != "") {
						var nokObj = request.response.vendor.nokia.agent[index];
						var nokTotal = nokObj.total;
					}
					if(request.response.vendor.zte.agent != "") {
						var zteObj = request.response.vendor.zte.agent[index];
						var zteTotal = zteObj.total;
					}
					if(request.response.vendor.rfc3877.agent != "") {
console.log("request");
						var RObj = request.response.vendor.rfc3877.agent[index];
						var rTotal = RObj.total;
					}
				}
console.log(RObj, rTotal );
				if(huwTotal != undefined || nokTotal != undefined || rTotal != undefined) {
					var totAge = nokTotal + huwTotal + rTotal;
				}
				if(nokTotal != undefined || zteTotal != undefined || rTotal != undefined) {
					var totAge = nokTotal + zteTotal + rTotal;
				}
				if(huwTotal != undefined || zteTotal != undefined || rTotal != undefined) {
					var totAge = huwTotal + zteTotal + rTotal;
				}
				if(huwTotal != undefined || zteTotal != undefined || nokTotal != undefined) {
					var totAge = huwTotal + zteTotal + nokTotal;
				} else {
					var totAge = huwTotal + nokTotal + zteTotal + rTotal;
				}
				var totSystem = {"name": "total", "count": totAge};
				var history = document.body.querySelector('snmp-collector')
							.shadowRoot.getElementById('agentList').history;
				var root1 = document.body.querySelector('snmp-collector')
							.shadowRoot.getElementById('agentList').shadowRoot;
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
							.shadowRoot.getElementById('agentList');
				var selected = sysEventType.shadowRoot.getElementById('vendorSelect').selected;
				var newRecord = new Object();
				if(selected == 0) {
					if(req.vendor.huawei.agent != "") {
						for(var index in req.vendor.huawei.agent) {
							var huwAgeEve = request.response.vendor.huawei.agent[index];
							if(huwAgeEve.eventType.communicationsAlarm != 0) {
								newRecord.communicationsAlarm = huwAgeEve.eventType
											.communicationsAlarm;
							}
							if(huwAgeEve.eventType.environmentalAlarm != 0) {
								newRecord.environmentalAlarm = huwAgeEve.eventType
											.environmentalAlarm;
							}
							if(huwAgeEve.eventType.equipmentAlarm != 0) {
								newRecord.equipmentAlarm = huwAgeEve.eventType.equipmentAlarm;
							}
							if(huwAgeEve.eventType.integrityViolation != 0) {
								newRecord.integrityViolation = huwAgeEve.eventType
											.integrityViolation;
							}
							if(huwAgeEve.eventType.operationalViolation!= 0) {
								newRecord.operationalViolation = huwAgeEve
											.eventType.operationalViolation;
							}
							if(huwAgeEve.eventType.physicalViolation != 0) {
								newRecord.physicalViolation = huwAgeEve.eventType.physicalViolation;
							}
							if(huwAgeEve.eventType.processingErrorAlarm != 0) {
								newRecord.processingErrorAlarm = huwAgeEve
											.eventType.processingErrorAlarm;
							}
							if(huwAgeEve.eventType.qualityofServiceAlarm != 0) {
								newRecord.qualityofServiceAlarm = huwAgeEve
											.eventType.qualityofServiceAlarm;
							}
							if(huwAgeEve.eventType.securityServiceOrMechanismViolation != 0) {
								newRecord.securityServiceOrMechanismViolation = huwAgeEve
											.eventType.securityServiceOrMechanismViolation;
							}
							if(huwAgeEve.eventType.timeDomainViolation != 0) {
								newRecord.timeDomainViolation = huwAgeEve
											.eventType.timeDomainViolation;
							}
							var dataEveAge = newRecord;
							var dataEventType = Object.keys(dataEveAge).map(k => ({name: k, count: dataEveAge[k]}));
						}
					}
				}
				if(selected == 1) {
					if(req.vendor.zte.agent != "") {
						for(var index in req.vendor.zte.agent) {
							var zteAgeEve = request.response.vendor.zte.agent[index];
							if(zteAgeEve.eventType.communicationsAlarm != 0) {
								newRecord.communicationsAlarm = zteAgeEve.eventType
											.communicationsAlarm;
							}
							if(zteAgeEve.eventType.environmentalAlarm != 0) {
								newRecord.environmentalAlarm = zteAgeEve.eventType
											.environmentalAlarm;
							}
							if(zteAgeEve.eventType.equipmentAlarm != 0) {
								newRecord.equipmentAlarm = zteAgeEve.eventType.equipmentAlarm;
							}
							if(zteAgeEve.eventType.integrityViolation != 0) {
								newRecord.integrityViolation = zteAgeEve.eventType
											.integrityViolation;
							}
							if(zteAgeEve.eventType.operationalViolation!= 0) {
								newRecord.operationalViolation = zteAgeEve
											.eventType.operationalViolation;
							}
							if(zteAgeEve.eventType.physicalViolation != 0) {
								newRecord.physicalViolation = zteAgeEve.eventType.physicalViolation;
							}
							if(zteAgeEve.eventType.processingErrorAlarm != 0) {
								newRecord.processingErrorAlarm = zteAgeEve
											.eventType.processingErrorAlarm;
							}
							if(zteAgeEve.eventType.qualityofServiceAlarm != 0) {
								newRecord.qualityofServiceAlarm = zteAgeEve
											.eventType.qualityofServiceAlarm;
							}
							if(zteAgeEve.eventType.securityServiceOrMechanismViolation != 0) {
								newRecord.securityServiceOrMechanismViolation = zteAgeEve
											.eventType.securityServiceOrMechanismViolation;
							}
							if(zteAgeEve.eventType.timeDomainViolation != 0) {
								newRecord.timeDomainViolation = zteAgeEve
											.eventType.timeDomainViolation;
							}
							var dataEveAge1 = newRecord;
							var dataEventType = Object.keys(dataEveAge1).map(k => ({name: k, count: dataEveAge1[k]}));
						}
					}
				}
				if(selected == 2) {
					if(req.vendor.nokia.agent != "") {
						for(var index in req.vendor.nokia.agent) {
							var nokAgeEve = request.response.vendor.nokia.agent[index];
							if(nokAgeEve.eventType.communicationsAlarm != 0) {
								newRecord.communicationsAlarm = nokAgeEve.eventType
											.communicationsAlarm;
							}
							if(nokAgeEve.eventType.environmentalAlarm != 0) {
								newRecord.environmentalAlarm = nokAgeEve.eventType
											.environmentalAlarm;
							}
							if(nokAgeEve.eventType.equipmentAlarm != 0) {
								newRecord.equipmentAlarm = nokAgeEve.eventType.equipmentAlarm;
							}
							if(nokAgeEve.eventType.integrityViolation != 0) {
								newRecord.integrityViolation = nokAgeEve.eventType
											.integrityViolation;
							}
							if(nokAgeEve.eventType.operationalViolation!= 0) {
								newRecord.operationalViolation = nokAgeEve
											.eventType.operationalViolation;
							}
							if(nokAgeEve.eventType.physicalViolation != 0) {
								newRecord.physicalViolation = nokAgeEve.eventType.physicalViolation;
							}
							if(nokAgeEve.eventType.processingErrorAlarm != 0) {
								newRecord.processingErrorAlarm = nokAgeEve
											.eventType.processingErrorAlarm;
							}
							if(nokAgeEve.eventType.qualityofServiceAlarm != 0) {
								newRecord.qualityofServiceAlarm = nokAgeEve
											.eventType.qualityofServiceAlarm;
							}
							if(nokAgeEve.eventType.securityServiceOrMechanismViolation != 0) {
								newRecord.securityServiceOrMechanismViolation = nokAgeEve
											.eventType.securityServiceOrMechanismViolation;
							}
							if(nokAgeEve.eventType.timeDomainViolation != 0) {
								newRecord.timeDomainViolation = nokAgeEve
											.eventType.timeDomainViolation;
							}
							var dataEveAge2 = newRecord;
							var dataEventType = Object.keys(dataEveAge2).map(k => ({name: k, count: dataEveAge2[k]}));
						}
					}
				}
				if(selected == 3) {
					if(req.vendor.rfc3877.agent != "") {
						for(var index in req.vendor.rfc3877.agent) {
							var nokAgeEve = request.response.vendor.rfc3877.agent[index];
							if(nokAgeEve.eventType.communicationsAlarm != 0) {
								newRecord.communicationsAlarm = nokAgeEve.eventType
											.communicationsAlarm;
							}
							if(nokAgeEve.eventType.environmentalAlarm != 0) {
								newRecord.environmentalAlarm = nokAgeEve.eventType
											.environmentalAlarm;
							}
							if(nokAgeEve.eventType.equipmentAlarm != 0) {
								newRecord.equipmentAlarm = nokAgeEve.eventType.equipmentAlarm;
							}
							if(nokAgeEve.eventType.integrityViolation != 0) {
								newRecord.integrityViolation = nokAgeEve.eventType
											.integrityViolation;
							}
							if(nokAgeEve.eventType.operationalViolation!= 0) {
								newRecord.operationalViolation = nokAgeEve
											.eventType.operationalViolation;
							}
							if(nokAgeEve.eventType.physicalViolation != 0) {
								newRecord.physicalViolation = nokAgeEve.eventType.physicalViolation;
							}
							if(nokAgeEve.eventType.processingErrorAlarm != 0) {
								newRecord.processingErrorAlarm = nokAgeEve
											.eventType.processingErrorAlarm;
							}
							if(nokAgeEve.eventType.qualityofServiceAlarm != 0) {
								newRecord.qualityofServiceAlarm = nokAgeEve
											.eventType.qualityofServiceAlarm;
							}
							if(nokAgeEve.eventType.securityServiceOrMechanismViolation != 0) {
								newRecord.securityServiceOrMechanismViolation = nokAgeEve
											.eventType.securityServiceOrMechanismViolation;
							}
							if(nokAgeEve.eventType.timeDomainViolation != 0) {
								newRecord.timeDomainViolation = nokAgeEve
											.eventType.timeDomainViolation;
							}
							var dataEveAge3 = newRecord;
							var dataEventType = Object.keys(dataEveAge3).map(k => ({name: k, count: dataEveAge3[k]}));
						}
					}
				}
				var root = document.body.querySelector('snmp-collector').shadowRoot
							.getElementById('agentList').shadowRoot;
				var color = scaleOrdinal(["#ff1744", "#ff9100", "#ffea00", "#00b0ff",
							"#33DCFF", "#33B2FF", "#FF33F7", "#FF338F", "#793030", "#2CF3FF"]);
				var svg = select(root).select("#vendorEvent");
				sysEventType.draw_pie(svg, dataEventType, color);

				var selectedVen = sysEventType.shadowRoot.getElementById('severeSelect').selected;
				var newRecord1 = new Object();
				if(selectedVen == 0) {
					if(req.vendor.huawei.agent != "") {
						for(var index in req.vendor.huawei.agent) {
							var huwAgeEve = request.response.vendor.huawei.agent[index];
							if(huwAgeEve.perceivedSeverity.major != 0) {
								newRecord1.major = huwAgeEve.perceivedSeverity
											.major;
							}
							if(huwAgeEve.perceivedSeverity.minor != 0) {
								newRecord1.minor = huwAgeEve.perceivedSeverity
											.minor;
							}
							if(huwAgeEve.perceivedSeverity.critical != 0) {
								newRecord1.critical = huwAgeEve.perceivedSeverity
											.critical;
							}
						}
					}
					var dataPer = newRecord1;
					var dataEventType = Object.keys(dataPer).map(k => ({ name: k, count: dataPer[k]}));
				}
				if(selectedVen == 1) {
					if(req.vendor.zte.agent != "") {
						for(var index in req.vendor.zte.agent) {
							var zteAgeEve = request.response.vendor.zte.agent[index];
							if(zteAgeEve.perceivedSeverity.major != 0) {
								newRecord1.major = zteAgeEve.perceivedSeverity
											.major;
							}
							if(zteAgeEve.perceivedSeverity.minor != 0) {
								newRecord1.minor = zteAgeEve.perceivedSeverity
											.minor;
							}
							if(zteAgeEve.perceivedSeverity.critical != 0) {
								newRecord1.critical = zteAgeEve.perceivedSeverity
											.critical;
							}
						}
					}
					var dataPerZte = newRecord1;
					var dataEventType = Object.keys(dataPerZte).map(k => ({ name: k, count: dataPerZte[k] }));
				}
				if(selectedVen == 2) {
					if(req.vendor.nokia.agent != "") {
						for(var index in req.vendor.nokia.agent) {
							var nokiaAgeEve = request.response.vendor.nokia.agent[index];
							if(nokiaAgeEve.perceivedSeverity.major != 0) {
								newRecord1.major = nokiaAgeEve.perceivedSeverity
											.major;
							}
							if(nokiaAgeEve.perceivedSeverity.minor != 0) {
								newRecord1.minor = nokiaAgeEve.perceivedSeverity
											.minor;
							}
							if(nokiaAgeEve.perceivedSeverity.critical != 0) {
								newRecord1.critical = nokiaAgeEve.perceivedSeverity
											.critical;
							}
						}
					}
					var dataPerNok = newRecord1;
					var dataEventType = Object.keys(dataPerNok).map(k => ({ name: k, count: dataPerNok[k] }));
				}
				if(selectedVen == 3) {
					if(req.vendor.rfc3877.agent != "") {
						for(var index in req.vendor.rfc3877.agent) {
							var nokiaAgeEve = request.response.vendor.rfc3877.agent[index];
							if(nokiaAgeEve.perceivedSeverity.major != 0) {
								newRecord1.major = nokiaAgeEve.perceivedSeverity
											.major;
							}
							if(nokiaAgeEve.perceivedSeverity.minor != 0) {
								newRecord1.minor = nokiaAgeEve.perceivedSeverity
											.minor;
							}
							if(nokiaAgeEve.perceivedSeverity.critical != 0) {
								newRecord1.critical = nokiaAgeEve.perceivedSeverity
											.critical;
							}
						}
					}
					var dataPerR = newRecord1;
					var dataEventType = Object.keys(dataPerR).map(k => ({ name: k, count: dataPerR[k] }));
				}
				var root = document.body.querySelector('snmp-collector').shadowRoot
							.getElementById('agentList').shadowRoot;
				var color = scaleOrdinal(["#ff1744", "#ff9100", "#ffea00", "#00b0ff",
							"#33DCFF", "#33B2FF", "#FF33F7", "#FF338F", "#793030", "#2CF3FF"]);
				var svg1 = select(root).select("#vendorSeverity");
				sysEventType.draw_pie(svg1, dataEventType, color);
				
			}
		}
		var handleAjaxError = function(error) {
			var toast = document.body.querySelector('snmp-collector').shadowRoot
						.getElementById('restError');
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

window.customElements.define('snmp-agentboard', agentBoard);
