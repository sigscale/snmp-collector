/**
 * @license
 * Copyright (c) 2018 The Polymer Project Authors. All rights reserved.
 * This code may only be used under the BSD style license found at http://polymer.github.io/LICENSE.txt
 * The complete set of authors may be found at http://polymer.github.io/AUTHORS.txt
 * The complete set of contributors may be found at http://polymer.github.io/CONTRIBUTORS.txt
 * Code distributed by Google as part of the polymer project is also
 * subject to an additional IP rights grant found at http://polymer.github.io/PATENTS.txt
 */

import { PolymerElement, html } from '@polymer/polymer/polymer-element.js';
import {} from '@polymer/polymer/lib/elements/dom-if.js';
import {} from '@polymer/polymer/lib/elements/dom-repeat.js';
import '@vaadin/vaadin-grid/vaadin-grid.js';
import '@vaadin/vaadin-grid/vaadin-grid-filter.js';
import '@vaadin/vaadin-grid/vaadin-grid-sorter.js';
import '@polymer/iron-ajax/iron-ajax.js';
import '@polymer/iron-icons/iron-icons.js';
import './style-element.js';

class mibList extends PolymerElement {
	static get template() {
		return html`
			<style include="style-element">
			</style>
			<vaadin-grid
					id="mibGrid"
					loading="{{!finishedLoading}}"
					active-item="{{activeItem}}">
				<template class="row-details">
					<dl class="details">
						<template is="dom-if" if={{item.name}}>
							<dt><b>Name</b></dt>
							<dd>{{item.name}}</dd>
						</template>
						<template is="dom-if" if={{item.mib_format_version}}>
							<dt><b>Mib format version</b></dt>
							<dd>{{item.mib_format_version}}</dd>
						</template>
						<template is="dom-if" if={{item.organization}}>
							<dt><b>Organization</b></dt>
							<dd>{{item.organization}}</dd>
						</template>
						<template is="dom-if" if={{item.description}}>
							<dt><b>Description</b></dt>
							<dd>{{item.description}}</dd>
						</template>
						<template is="dom-if" if={{item.last}}>
							<dt><b>Last</b></dt>
							<dd>{{item.last}}</dd>
						</template>
						<template is="dom-if" if={{item.asn1_types}}>
							<dt><b>Asn Types</b></dt>
							<dd>{{item.asn1_types}}</dd>
						</template>
					</dl>
				</template>
				<vaadin-grid-column width="12ex" flex-grow="3">
					<template class="header">
						<vaadin-grid-sorter
								path="name">
							<vaadin-grid-filter
									id="filterName"
									aria-label="Name"
									path="filterName"
									value="{{_filterName}}">
								<input
										slot="filter"
										placeholder="Name"
										value="{{_filterName::input}}"
										focus-target>
							</vaadin-grid-filter>
						</vaadin-grid-sorter>
					</template>
					<template>
						<div>
							[[item.name]]
						</div>
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="10ex" flex-grow="2">
					<template class="header">
						<vaadin-grid-sorter
								path="organization">
							<vaadin-grid-filter
									id="filterOrg"
									aria-label="Organization"
									path="filterOrg"
									value="{{_filterOrg}}">
								<input
										slot="filter"
										placeholder="Organization"
										value="{{_filterOrg::input}}"
										focus-target>
							</vaadin-grid-filter>
						</vaadin-grid-sorter>
					</template>
					<template>
						<div>
							[[item.organization]]
						</div>
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="30ex" flex-grow="3">
					<template class="header">
						<vaadin-grid-sorter
								path="description">
							<vaadin-grid-filter
									id="filterDesc"
									aria-label="Description"
									path="filterDesc"
									value="{{_filterDesc}}">
								<input
										slot="filter"
										placeholder="Description"
										value="{{_filterDesc::input}}"
										focus-target>
							</vaadin-grid-filter>
						</vaadin-grid-sorter>
					</template>
					<template>
						<div>
							[[item.description]]
						</div>
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="8ex" flex-grow="1">
					<template class="header">
						<vaadin-grid-sorter
								path="last">
							<vaadin-grid-filter
									id="filterLast"
									aria-label="lastUpdated"
									path="filterLast"
									value="{{_filterLast}}">
								<input
										slot="filter"
										placeholder="LastUpdated"
										value="{{_filterLast::input}}"
										focus-target>
							</vaadin-grid-filter>
						</vaadin-grid-sorter>
					</template>
					<template>
						<div>
							[[item.last]]
						</div>
					</template>
				</vaadin-grid-column>
				<vaadin-grid-column width="5ex" flex-grow="1">
					<template class="header">
						<vaadin-grid-sorter
								path="traps">
							<vaadin-grid-filter
									id="filter"
									aria-label="lastTraps"
									path="filterTraps"
									value="{{_filterTraps}}">
								<input
										slot="filter"
										placeholder="Traps"
										value="{{_filterTraps::input}}"
										focus-target>
							</vaadin-grid-filter>
						</vaadin-grid-sorter>
					</template>
					<template>
						<div>
							[[item.traps]]
						</div>
					</template>
				</vaadin-grid-column>
			</vaadin-grid>
			<iron-ajax
				id="getMibAjax"
				url="snmp/v1/mibs"
				rejectWithRequest>
			</iron-ajax>
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
			var grid = this.shadowRoot.getElementById('mibGrid');
			var current;
			if(item == null) {
				current = last;
			} else {
				current = item
			}
			function checkExist(mib) {
				return mib.id == current.id;
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
		var grid = this.shadowRoot.getElementById('mibGrid');
		var ajaxGrid = this.shadowRoot.getElementById('getMibAjax');
		grid.dataProvider = this._getMibList;
	}

	_getMibList(params, callback) {
		var grid = this;
		var ajax = document.body.querySelector('snmp-collector').shadowRoot.querySelector('mib-list').shadowRoot.getElementById('getMibAjax');
		var mibList1 = document.body.querySelector('snmp-collector').shadowRoot.querySelector('mib-list');
		var handleAjaxResponse = function(request) {
			if (request){
				mibList1.etag = request.xhr.getResponseHeader('ETag');
				var range = request.xhr.getResponseHeader('Content-Range');
				var range1 = range.split("/");
				var range2 = range1[0].split("-");
				if (range1[1] != "*") {
					grid.size = Number(range1[1]);
				} else {
					grid.size = Number(range2[1]) + grid.pageSize * 2;
				}
				var vaadinItems = new Array();
				for(var index in request.response) {
					var newRecord = new Object();
					if(request.response[index].name) {
						newRecord.name = request.response[index].name;
					}
					if(request.response[index].mib_format_version) {
						newRecord.mib_format_version = request.response[index].mib_format_version;
					}
					if(request.response[index].module_identity) {
						if(request.response[index].module_identity.organization) {
							newRecord.organization = request.response[index].module_identity.organization;
						}
						if(request.response[index].module_identity.description) {
							newRecord.description = request.response[index].module_identity.description;
						}
						if(request.response[index].module_identity.last_updated) {
							newRecord.last= request.response[index].module_identity.last_updated;
						}
					}
					if(request.response[index].traps) {
						var trapCount = request.response[index].traps;
						newRecord.traps = trapCount.length;
					}
					if(request.response[index].asn1_types) {
						var asnArr = request.response[index].asn1_types;
						newRecord.asn1_types = asnArr.toString(); 
					}
					vaadinItems[index] = newRecord;
				}
				callback(vaadinItems);
			} else {
				grid.size = 0;
				callback([]);
			}
		};
		var handleAjaxError = function(error) {
			mibList1.etag = null;
			var toast;
			toast.text = "error"
			toast.open();
			if(!grid.size) {
				 grid.size = 0;
			}
			callback([]);
		}
		if(ajax.loading) {
			ajax.lastRequest.completes.then(function(request) {
				var startRange = params.page * params.pageSize + 1;
				var endRange = startRange + params.pageSize - 1;
				ajax.headers['Range'] = "items=" + startRange + "-" + endRange;
				if (alarmList1.etag && params.page > 0) {
					ajax.headers['If-Range'] = alarmList1.etag;
				} else {
					delete ajax.headers['If-Range'];
				}
				return ajax.generateRequest().completes;
				}, handleAjaxError).then(handleAjaxResponse, handleAjaxError);
			} else {
				var startRange = params.page * params.pageSize + 1;
				var endRange = startRange + params.pageSize - 1;
				ajax.headers['Range'] = "items=" + startRange + "-" + endRange;
				if (mibList1.etag && params.page > 0) {
					ajax.headers['If-Range'] = mibList1.etag;
				} else {
					delete ajax.headers['If-Range'];
				}
				ajax.generateRequest().completes.then(handleAjaxResponse, handleAjaxError);
			}
	}
}

window.customElements.define('mib-list', mibList);

