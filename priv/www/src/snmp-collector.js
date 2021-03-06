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
import '@polymer/iron-collapse/iron-collapse.js';
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
							<div main-title>[[viewTitle]]</div>
							<paper-icon-button
									icon="my-icons:refresh"
									on-click="refreshClick">
							</paper-icon-button>
							<paper-icon-button
									toggles
									id="overFlowIcon"
									active="{{overFlowActive}}"
									on-click="_overFlowMenu"
									icon="my-icons:overFlowMenu">
							</paper-icon-button>
						</app-toolbar>
					</app-header>
					<iron-pages
							id="load"
							selected="[[page]]"
							attr-for-selected="name"
							role="main">
						<snmp-systemboard
								id="systemList"
								loading="{{systemLoading}}"
								name="systemView">
						</snmp-systemboard>
						<snmp-vendorboard
								id="vendorList"
								loading="{{vendorLoading}}"
								name="vendorView">
						</snmp-vendorboard>
						<snmp-agentboard
								id="agentList"
								loading="{{agentLoading}}"
								name="agentView">
						</snmp-agentboard>
						<mib-list
								id="mibList"
								finished-loading="{{progress}}"
								name="mibView">
						</mib-list>
						<user-list
								id="userList"
								finished-loading="{{progress}}"
								name="userView">
						</user-list>
						<log-list
								id="logList"
								loading="{{logLoading}}"
								name="logView">
						</log-list>
						<http-list
								id="httpList"
								loading="{{httpLoading}}"
								name="httpView">
						</http-list>
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
						<a on-click="_collapseLogs">
							<paper-icon-button
								icon="my-icons:dashboard">
							</paper-icon-button>
							Dashboard
						</a>
						<iron-collapse id="dash">
							<a name="systemView" href="[[rootPath]]systemView">
								<paper-icon-button
									icon="my-icons:data">
								</paper-icon-button>
								System
							</a>
							<a name="vendorView" href="[[rootPath]]vendorView">
								<paper-icon-button
									icon="my-icons:data">
								</paper-icon-button>
								Vendor
							</a>
							<a name="agentView" href="[[rootPath]]agentView">
								<paper-icon-button
									icon="my-icons:data">
								</paper-icon-button>
								Agent
							</a>
						</iron-collapse>
						<a name="mibView" href="[[rootPath]]mibView">
							<paper-icon-button
									icon="my-icons:mibIcon">
							</paper-icon-button>
							MIBs
						</a>
						<a name="userView" href="[[rootPath]]userView">
							<paper-icon-button
									icon="my-icons:users">
							</paper-icon-button>
							User
						</a>
						<a on-click="_collapseLogs">
							<paper-icon-button
								icon="my-icons:logIcon">
							</paper-icon-button>
							Logs
						</a>
						<iron-collapse id="logs">
							<a name="logView" href="[[rootPath]]logView">
								<paper-icon-button
									icon="my-icons:data">
								</paper-icon-button>
								Events
							</a>
							<a name="httpView" href="[[rootPath]]httpView">
								<paper-icon-button
									icon="my-icons:logIcon">
								</paper-icon-button>
								HTTP
							</a>
						</iron-collapse>
					</iron-selector>
				</app-drawer>
			</app-drawer-layout>
			<!-- Modal Definitions -->
			<snmp-collector-help id="snmpGetHelp" active="[[overFlowActive]]"></snmp-collector-help>
		`;
	}

	_collapseLogs(event) {
		var snmp = document.body.querySelector('snmp-collector');
		var dashObj = snmp.shadowRoot.getElementById('dash');
		if(dashObj.opened == false) {
			dashObj.show();
		} else {
			dashObj.hide();
		}
		var logObj = snmp.shadowRoot.getElementById('logs');
		if(logObj.opened == false) {
			logObj.show();
		} else {
			logObj.hide();
		}
	}

	refreshClick() {
		switch(this.$.load.selected) {
         case "systemView":
            var dash = this.shadowRoot.getElementById('systemList');
            if (!dash.loading) {
               dash._load();
            } else {
               console.log('Have patience dude!');
            }
            break;
         case "vendorView":
            var ven = this.shadowRoot.getElementById('vendorList');
            if (!ven.loading) {
               ven._load();
            } else {
               console.log('Have patience dude!');
            }
            break;
         case "agentView":
            var age = this.shadowRoot.getElementById('agentList');
            if (!age.loading) {
               age._load();
            } else {
               console.log('Have patience dude!');
            }
            break;
			case "mibView":
				this.shadowRoot.getElementById('mibList').shadowRoot.getElementById('mibGrid').clearCache();
				break;
			case "logView":
				this.shadowRoot.getElementById('logList').shadowRoot.getElementById('logGrid').clearCache();
				break;
			case "userView":
				this.shadowRoot.getElementById('userList').shadowRoot.getElementById('userGrid').clearCache();
				break;
			case "httpView":
				this.shadowRoot.getElementById('httpList').shadowRoot.getElementById('httpGrid').clearCache();
				break;
		}
	}

	static get properties() {
		return {
			viewTitle: {
			type: String
			},
			page: {
				type: String,
				reflectToAttribute: true,
				observer: '_pageChanged'
			},
			routeData: Object,
			ubroute: Object,
         loading: {
            type: String,
            value: false
         },
			logLoading: {
				type: String,
			},
			httpLoading: {
				type: String,
			}
		};
	}

	static get observers() {
		return [
			'_routePageChanged(routeData.page)',
			'_loadingChanged(dashLoading, logLoading, httpLoading)'
		];
	}

	_routePageChanged(page) {
		// Show the corresponding page according to the route.
		//
		// If no page was found in the route data, page will be an empty string.
		// Show 'mibView' in that case. And if the page doesn't exist, show 'view404'.
		if (!page) {
			this.page = 'mibView';
		} else if (['vendorView',
					'systemView',
					'agentView',
					'mibView',
					'userView',
					'logView',
					'httpView'].indexOf(page) !== -1) {
			this.page = page;
		}
		switch (this.page) {
			case 'vendorView':
				this.viewTitle = "Vendor";
				break;
			case 'systemView':
				this.viewTitle = "System";
				break;
			case 'agentView':
				this.viewTitle = "Agent";
				break;
			case 'mibView':
				this.viewTitle = "MIBs";
				break;
			case 'userView':
				this.viewTitle = "Users";
				break;
			case 'logView':
				this.viewTitle = "Logs";
				break;
			case 'httpView':
				this.viewTitle = "HTTP Log";
				break;
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
			case 'vendorView':
				import('./snmp-vendorboard.js');
				break;
			case 'systemView':
				import('./snmp-systemboard.js');
				break;
			case 'agentView':
				import('./snmp-agentboard.js');
				break;
			case 'mibView':
				import('./mib-list.js');
				break;
			case 'logView':
				import('./log-list.js');
				break;
			case 'userView':
				import('./user-list.js');
				break;
			case 'httpView':
				import('./http-list.js');
				break
			}
		}

	_loadingChanged() {
		if(this.dashLoading) {
			this.loading = true;
		} else {
			this.loading = false;
		}
		if(this.logLoading) {
			this.loading = true;
		} else {
			this.loading = false;
		}
	}

	_overFlowMenu() {
		import('./snmp-collector-help.js');
	}
}

window.customElements.define('snmp-collector', SnmpCollector);

