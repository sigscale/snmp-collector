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
import "@polymer/paper-card/paper-card.js";
import "@polymer/paper-item/paper-icon-item.js";
import '@polymer/iron-ajax/iron-ajax.js';
import './style-element.js';

class systemBoard extends PolymerElement {
	static get template() {
		return html`
			<style include="style-element">
			</style>
			<paper-card heading="Event Type">
				<div class="card-content">
					<svg id="metric" width="800" height="260"></svg>
				</div>
			</paper-card>
			<paper-card heading="Severity">
				<div class="card-content">
					<svg id="severity" width="500" height="260"></svg>
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
		}
	}

	ready() {
		super.ready();
		this._load();
	}

	_load() {
		var ajax = document.body.querySelector('snmp-collector').shadowRoot.getElementById('systemList').shadowRoot.getElementById('getDashAjax');
		var handleAjaxResponse = function(request) {
			if (request) {
				var dataArray = new Array();
				var req = request.response;
				var dataEventType = Object.keys(req.eventType).map(k => ({ name: k, count: req.eventType[k] }));
				var sysEventType = document.body.querySelector('snmp-collector').shadowRoot.getElementById('systemList');
				var root = document.body.querySelector('snmp-collector').shadowRoot.getElementById('systemList').shadowRoot;
				var color = scaleOrdinal(["#ff1744", "#ff9100", "#ffea00", "#00b0ff", "#33DCFF", "#33B2FF", "#FF33F7", "#FF338F", "#793030", "#2CF3FF"]);
				var svg = select(root).select("#metric");
				sysEventType.draw_pie(svg, dataEventType, color);

				var dataSeverity = Object.keys(req.perceivedSeverity).map(k1 => ({ name: [k1], count: req.perceivedSeverity[k1] }));
				var sysSev = document.body.querySelector('snmp-collector').shadowRoot.getElementById('systemList');
				var root = document.body.querySelector('snmp-collector').shadowRoot.getElementById('systemList').shadowRoot;
				var colorSev = scaleOrdinal(["#ff1744", "#ff9100", "#ffea00"]);
				var svgSev = select(root).select("#severity");
				sysSev.draw_pie(svgSev, dataSeverity, colorSev);
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

window.customElements.define('snmp-systemboard', systemBoard);
