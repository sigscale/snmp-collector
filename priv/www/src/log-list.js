/**
 * @license
 * Copyright (c) 2016 The Polymer Project Authors. All rights reserved.
 * This code may only be used under the BSD style license found at http://polymer.github.io/LICENSE.txt
 * The complete set of authors may be found at http://polymer.github.io/AUTHORS.txt
 * The complete set of contributors may be found at http://polymer.github.io/CONTRIBUTORS.txt
 * Code distributed by Google as part of the polymer project is also
 * subject to an additional IP rights grant found at http://polymer.github.io/PATENTS.txt
 */

import { PolymerElement, html } from '@polymer/polymer/polymer-element.js';
import '@vaadin/vaadin-grid/vaadin-grid.js';
import '@vaadin/vaadin-grid/vaadin-grid-filter.js';
import '@vaadin/vaadin-lumo-styles/color.js'
import '@polymer/polymer/lib/elements/dom-repeat.js';
import '@polymer/paper-toast/paper-toast.js';
import './style-element.js';

class logs extends PolymerElement {
	static get template() {
		return html`
			<style include="shared-styles">
				:host {
					display: block;
				}
				input::placeholder {
					color: black;
					font-weight: 500;
					font-size: inherit;
				}
				vaadin-grid {
					height: 100vh; 
					font-size: inherit;
				}
				vaadin-grid input {
					font-size: inherit;
					border-style: none;
				}
				.timestamplog {
					direction: rtl;
				}
			</style>
			<vaadin-grid
					id="logGrid"
					loading="{{!finishedLoading}}"
					active-item="{{activeItem}}">
				<template class="row-details">
					<template is="dom-repeat" items="{{item.alarmAdditionalInformation}}">
						<dl class="details">
							<dt>{{item.name}}</dt>
							<dd>{{item.value}}</dd>
						</dl>
					</template>
				</template>
				<vaadin-grid-column width="20ex" flex-grow="2">
					<template class="header">
						<vaadin-grid-filter
								id="filterEventId"
								aria-label="Event ID"
								path="eventId"
								value="{{_filterEventId}}">
							 <input
									slot="filter"
									placeholder="Event ID"
									value="{{_filterEventId::input}}"
									focus-target>
						</vaadin-grid-filter>
					</template>
					<template>
						<div class="timestamplog"}">
							<bdo dir="ltr">[[item.eventId]]</bdo>
						</div>
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="10ex" flex-grow="1">
					<template class="header">
						<vaadin-grid-filter
								id="filterEventName"
								aria-label="Source ID"
								path="eventName"
								value="{{_filterEventName}}">
							 <input
									slot="filter"
									placeholder="Source ID"
									value="{{_filterEventName::input}}"
									focus-target>
						</vaadin-grid-filter>
					</template>
					<template>
						[[item.eventName]]
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="10ex" flex-grow="1">
					<template class="header">
						<vaadin-grid-filter
								id="filterPriority"
								aria-label="Priority"
								path="priority"
								value="{{_filterPriority}}">
							 <input
									slot="filter"
									placeholder="Priority"
									value="{{_filterPriority::input}}"
									focus-target>
						</vaadin-grid-filter>
					</template>
					<template>
						[[item.priority]]
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="18ex" flex-grow="2">
					<template class="header">
						<vaadin-grid-filter
								id="filterSourceName"
								aria-label="Source Name"
								path="sourceName"
								value="{{_filterSourceName}}">
							 <input
									slot="filter"
									placeholder="Source Name"
									value="{{_filterSourceName::input}}"
									focus-target>
						</vaadin-grid-filter>
					</template>
					<template>
						[[item.sourceName]]
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="10ex" flex-grow="1">
					<template class="header">
						<vaadin-grid-filter
								id="filterReport"
								aria-label="Reporting Name"
								path="reportingEntityName"
								value="{{_filterReport}}">
							 <input
									slot="filter"
									placeholder="Reporting Name"
									value="{{_filterReport::input}}"
									focus-target>
						</vaadin-grid-filter>
					</template>
					<template>
						[[item.reportingEntityName]]
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="12ex" flex-grow="2">
					<template class="header">
						<vaadin-grid-filter
								id="filterTime"
								aria-label="Timestamp"
								path="lastEpoch"
								value="{{_filterTime}}">
							 <input
									slot="filter"
									placeholder="Timestamp"
									value="{{_filterTime::input}}"
									focus-target>
						</vaadin-grid-filter>
					</template>
					<template>
						<div class="timestamplog">
							<bdo dir="ltr">[[item.lastEpoch]]</bdo>
						</div>
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="15ex" flex-grow="1">
					<template class="header">
						<vaadin-grid-filter
								id="filterAlarmCon"
								aria-label="Alarm Condition"
								path="alarmCondition"
								value="{{_filterAlarmCon}}">
							 <input
									slot="filter"
									placeholder="Alarm Condition"
									value="{{_filterAlarmCon::input}}"
									focus-target>
						</vaadin-grid-filter>
					</template>
					<template>
						[[item.alarmCondition]]
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="10ex" flex-grow="1">
					<template class="header">
						<vaadin-grid-filter
								id="filterSeverity"
								aria-label="Severity"
								path="eventSeverity"
								value="{{_filterSeverity}}">
							 <input
									slot="filter"
									placeholder="Severity"
									value="{{_filterSeverity::input}}"
									focus-target>
						</vaadin-grid-filter>
					</template>
					<template>
						[[item.eventSeverity]]
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="23ex" flex-grow="3">
					<template class="header">
						<vaadin-grid-filter
								id="filterSpecific"
								aria-label="Specific Problem"
								path="specificProblem"
								value="{{_filterSpecific}}">
							 <input
									slot="filter"
									placeholder="Specific Problem"
									value="{{_filterSpecific::input}}"
									focus-target>
						</vaadin-grid-filter>
					</template>
					<template>
						[[item.specificProblem]]
					</template>
				</vaadin-grid-column>
			</vaadin-grid>
		`;
	}
	
	static get properties() {
		return {
			finishedLoading: {
				type: Boolean,
				notify: true
			},
			activeItem: {
				type: Boolean,
				observer: '_activeItemChanged'
			}
		}
	}
	
	_activeItemChanged(item, last) {
		if(item || last) {
			var grid = this.shadowRoot.getElementById('logGrid');
			var current;
			if(item == null) {
				current = last;
			} else {
				current = item
			}
			function checkExist(log) {
				return log.id == current.id;
			}
			if(grid.detailsOpenedItems && grid.detailsOpenedItems.some(checkExist)) {
				grid.closeItemDetails(current);
			} else {
				grid.openItemDetails(current);
			}
		}
	}

	ready() {
		super.ready();
		var grid = this.shadowRoot.getElementById('logGrid');
		grid.dataProvider = this._getLogList;
	}

	_getLogList(params, callback) {
		var grid = this;
		var url = "eventManagement/v1/event";
		var query = "";
		var StartRange = params.page * params.pageSize + 1;
		var EndRange = StartRange + params.pageSize - 1;
		function checkHead(param) {
			return param.path == "eventId" || param.path == "eventName";
		}
		params.filters.filter(checkHead).forEach(function(filter) {
			if (query) {
				query = query + "%5D%2C" + filter.path + ".like%3D%5B" + filter.value + "%25";
			} else {
				query = "%5B%7B" + filter.path + ".like%3D%5B" + filter.value + "%25";
			}
		});
		if(query) {
			url += "?filter=%22" + query + "%5D%7D%5D%22";
		}
		fetch(url, {
				method: "GET",
				headers: {"accept": "application/json", "Range": "items=" + StartRange + "-" + EndRange},
				credentials: "same-origin"
			}).then(function(response) {
				if(response.ok) {
					var range = response.headers.get('Content-Range');
					var range1 = range.split("/");
					var range2 = range1[0].split("-");
					if (range1[1] != "*") {
						grid.size = Number(range1[1]);
					} else {
						grid.size = Number(range2[1]) + grid.pageSize * 2;
					}
					return response.json();
				} else {
					var error = new Error(response.statusText);
					error.response = response;
					throw error;
				}
			}).then(function(json) {
				var vaadinItems = new Array();
				for(var index in json) {
					var newRecord = new Object();
					newRecord.id = json[index].id;
					newRecord.eventId = json[index].eventId;
					newRecord.sourceName = json[index].sourceSystem;
					newRecord.lastEpoch = json[index].lastEpochMicrosec;
					newRecord.eventName = json[index].eventName;
					newRecord.priority = json[index].priority;
					newRecord.reportingEntityName = json[index].reportingEntityName;
					function getChar(char) {
						newRecord[char.name] = char.value; 
					}
					json[index].eventCharacteristic.forEach(getChar);
					vaadinItems[index] = newRecord;
				}
				callback(vaadinItems);
			}).catch(function(error) {
				var snmp = document.body.querySelector('snmp-collector');
				snmp.shadowRoot.getElementById('restError').text = error.message;
				snmp.shadowRoot.getElementById('restError').open();
				var vaadinItems = new Array();
				grid.size = 0;
				console.log('Looks like there was a problem: \n', error);
				callback(vaadinItems);
			});
	}
}

window.customElements.define('log-list', logs);
