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
import { setPassiveTouchGestures, setRootPath } from '@polymer/polymer/lib/utils/settings.js';
import '@polymer/app-layout/app-drawer/app-drawer.js';
import '@polymer/app-layout/app-drawer-layout/app-drawer-layout.js';
import '@polymer/app-layout/app-header/app-header.js';
import '@polymer/app-layout/app-header-layout/app-header-layout.js';
import '@polymer/app-layout/app-scroll-effects/app-scroll-effects.js';
import '@polymer/app-layout/app-toolbar/app-toolbar.js';
import '@polymer/paper-styles/typography.js';
import '@polymer/app-route/app-location.js';
import '@polymer/app-route/app-route.js';
import '@polymer/iron-pages/iron-pages.js';
import '@polymer/iron-selector/iron-selector.js';
import '@polymer/paper-icon-button/paper-icon-button.js';
import '@polymer/paper-progress/paper-progress.js';
import '@polymer/paper-toast/paper-toast.js';
import './snmp-collector-icons.js';
import './style-element.js';

// Gesture events like tap and track generated from touch will not be
// preventable, allowing for better scrolling performance.
setPassiveTouchGestures(true);

// Set Polymer's root path to the same value we passed to our service worker
// in `index.html`.
setRootPath(MyAppGlobals.rootPath);

class SnmpCollector extends PolymerElement {
	static get template() {
		return html`
			<style include="style-element">
			</style>
			<app-location
					route="{{route}}"
					url-space-regex="^[[rootPath]]">
			</app-location>
			<app-route
					route="{{route}}"
					pattern="[[rootPath]]:page"
					data="{{routeData}}"
					tail="{{subroute}}">
			</app-route>
			<app-drawer-layout
					force-narrow
					fullbleed>
				<app-header-layout
						has-scrolling-region>
					<app-header
							slot="header"
							condenses
							reveals
							effects="waterfall">
						<app-toolbar
								class="toolbar-top">
							<paper-icon-button
									icon="my-icons:menu"
									drawer-toggle>
							</paper-icon-button>
							<div main-title>SNMP Collector</div>
							<paper-icon-button
									icon="my-icons:refresh"
									on-click="refreshClick">
							</paper-icon-button>
						</app-toolbar>
					</app-header>
					<iron-pages
							id="load"
							selected="[[page]]"
							attr-for-selected="name"
							role="main">
						<mib-list
								id="mibList"
								finished-loading="{{progress}}"
								name="mibView">
						</mib-list>
						<log-list
								id="logList"
								finished-loading="{{progress}}"
								name="logView">
						</log-list>
						<user-list
								id="userList"
								finished-loading="{{progress}}"
								name="userView">
						</user-list>
					</iron-pages>
					<paper-toast
							id="restError"
							class="fit-bottom"
							duration="8000">
					</paper-toast>
				</app-header-layout>
				<app-drawer
						id="drawer"
						slot="drawer">
					<iron-selector
							selected="[[page]]"
							attr-for-selected="name"
							class="drawer-list"
							role="navigation">
						<a name="mibView" href="[[rootPath]]mibView">
							<paper-icon-button
									icon="my-icons:mibIcon">
							</paper-icon-button>
							MIBs
						</a>
						<a name="logView" href="[[rootPath]]logView">
							<paper-icon-button
									icon="my-icons:logIcon">
							</paper-icon-button>
							Logs
						</a>
						<a name="userView" href="[[rootPath]]userView">
							<paper-icon-button
									icon="my-icons:users">
							</paper-icon-button>
							User
						</a>
					</iron-selector>
				</app-drawer>
				<paper-progress
						id="pro"
						indeterminate
						class="slow red"
						disabled="{{progress}}">
				</paper-progress>
			</app-drawer-layout>
		`;
	}

	refreshClick() {
		switch(this.$.load.selected) {
			case "mibView":
				this.shadowRoot.getElementById('mibList').shadowRoot.getElementById('mibGrid').clearCache();
				break;
			case "logView":
				this.shadowRoot.getElementById('logList').shadowRoot.getElementById('logGrid').clearCache();
				break;
			case "userView":
				this.shadowRoot.getElementById('userList').shadowRoot.getElementById('userGrid').clearCache();
				break;
		}
	}

	static get properties() {
		return {
			page: {
				type: String,
				reflectToAttribute: true,
				observer: '_pageChanged'
			},
			routeData: Object,
			ubroute: Object
		};
	}

	static get observers() {
		return [
			'_routePageChanged(routeData.page)'
		];
	}

	_routePageChanged(page) {
		// Show the corresponding page according to the route.
		//
		// If no page was found in the route data, page will be an empty string.
		// Show 'mibView' in that case. And if the page doesn't exist, show 'view404'.
		if (!page) {
			this.page = 'mibView';
		} else if (['mibView', 'logView', 'userView'].indexOf(page) !== -1) {
			this.page = page;
		}
		// Close a non-persistent drawer when the page & route are changed.
		if (!this.$.drawer.persistent) {
			this.$.drawer.close();
		}
	}

	_pageChanged(page) {
		// Import the page component on demand.
		//
		// Note: `polymer build` doesn't like string concatenation in the import
		// statement, so break it up.
		switch (page) {
			case 'mibView':
				import('./mib-list.js');
				break;
			case 'logView':
				import('./log-list.js');
				break;
			case 'userView':
				import('./user-list.js');
				break;
			}
		}
	}

window.customElements.define('snmp-collector', SnmpCollector);

