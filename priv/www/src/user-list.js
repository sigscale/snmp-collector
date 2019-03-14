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
import './style-element.js';

class userList extends PolymerElement {
	static get template() {
		return html`
			<style include="shared-styles">
				:host {
					display: block;
				}
				vaadin-grid {
					height: 100vh; 
					font-size: inherit;
				}
			</style>
			<vaadin-grid id="userGrid" loading="{{!finishedLoading}}">
				<vaadin-grid-column>
					<template class="header">
						User name
					</template>
					<template>[[item.id]]</template>
				</vaadin-grid-column>
				<vaadin-grid-column>
					<template class="header">
						Language
					</template>
					<template>[[item.language]]</template>
				</vaadin-grid-column>
			</vaadin-grid>
		`;
	}

	static get properties() {
		return {
			finishedLoading: {
				type: Boolean,
				notify: true
			}
		}
	}

	ready() {
		super.ready();
		var grid = this.shadowRoot.getElementById('userGrid');
		grid.dataProvider = this._getLog;
	}

	_getLog(params, callback) {
		var grid = this;
		var StartRange = params.page * params.pageSize + 1;
		var EndRange = StartRange + params.pageSize - 1;
		fetch("partyManagement/v1/individual", {
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
				function checkChar(characteristic){
					return characteristic.name == "locale";
				}
				for(var index in json) {
					var newRecord = new Object();
					newRecord.id = json[index].id;
					var langChar = json[index].characteristic.find(checkChar);
					if(langChar != undefined) {
						newRecord.language = langChar.value;
					}
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

window.customElements.define('user-list', userList);
