const styleElement = document.createElement('dom-module');
styleElement.setAttribute('theme-for', 'vaadin-grid');

styleElement.innerHTML = `<template>
		<style>
			:host {
				@apply(--paper-font-common-base);
				--app-primary-color: #f57f17;
				--app-secondary-color: #aeea00;
				display: block;
			}
			app-header {
				position: fixed;
				top: 0;
				left: 0;
				width: 100%;
				text-align: center;
				background-color: var(--app-primary-color);
				border-bottom: 1px solid #eee;
				color: #fff;
			}
			.toolbar-top {
				background-color: var(--app-primary-color);
			}
			app-header paper-icon-button {
				--paper-icon-button-ink-color: white;
			}
			app-drawer {
				--app-drawer-content-container: {
					padding-top: 10px;
				};
				height: 100%;
				top: 64px;
			}
			paper-progress {
				display: block;
				width: 100%;
				--paper-progress-active-color: var(--paper-lime-a700);
				--paper-progress-container-color: transparent;
			}
			.drawer-list {
				box-sizing: border-box;
				width: 100%;
				height: 100%;
				background: white;
				position: relative;
			}
			.drawer-list a {
				display: block;
				text-decoration: none;
				color: black;
				padding-left: 24px;
			}
			.drawer-list a.iron-selected {
				color: #78909C;
				font-weight: bold;
			}
			.drawer-list iron-collapse#logs {
				padding-left: 36px;
			}
			.drawer-list iron-collapse#dash {
				padding-left: 36px;
			}
			#restError {
				--paper-toast-background-color: var(--paper-red-a400);
			}
			paper-dialog {
            position: fixed;
            min-width: 20em;
            right: -36px;
            top: 41px;
            overflow: auto;
            padding: 0px;
				display: inline-grid;
         }
			paper-dialog > *:first-child {
            margin-top: 0px;
         }
			paper-toolbar {
            color: white;
            background-color: #bc5100;
         }
			iron-icon {
            padding-right: 10px;
         }
			paper-dropdown-menu {
				--paper-input-container-label: {
					font-size: 24px;
				};
				--paper-input-container-input: {
					font-size: 24px;
					font-weight: 400;
				};
			}
			.grouptitle {
				text-align: center;
				border-bottom-style: solid;
				border-color: var(--paper-yellow-900);
			}
			vaadin-grid {
				height: 100vh;
				font-size: inherit;
			}
			vaadin-grid input {
				font-size: initial;
				border-style: none;
				background: #ffb04c;
				max-width: 130px;
			}
			vaadin-grid input::placeholder {
				color: black;
            font-weight: bold;
            font-size: inherit;
			}
			[part~="header-cell"] {
				background-color: #ffb04c;
			}
			vaadin-grid [severity=critical],[severity=CRITICAL] {
				background-color: #ff1744;
				padding: 10px 15px;
				top: 0;
				left: 0;
				bottom: 0;
				right: 0;
				position: absolute;
				z-index: 1;
				overflow: hidden;
			}
			vaadin-grid [severity=major],[severity=MAJOR] {
				background-color: #ff9100;
				padding: 10px 15px;
				top: 0;
				left: 0;
				bottom: 0;
				right: 0;
				position: absolute;
				z-index: 1;
				overflow: hidden;
			}
			vaadin-grid [severity=minor],[severity=MINOR] {
				background-color: #ffea00;
				padding: 10px 15px;
				top: 0;
				left: 0;
				bottom: 0;
				right: 0;
				position: absolute;
				z-index: 1;
				overflow: hidden;
			}
			vaadin-grid [severity=warning],[severity=WARNING] {
				background-color: #00b0ff;
				padding: 10px 15px;
				top: 0;
				left: 0;
				bottom: 0;
				right: 0;
				position: absolute;
				z-index: 1;
				overflow: hidden;
			}
			paper-fab {
            background: var(--paper-lime-a700);
            color: black;
         }
         .add-button {
            right: 2%;
            position: fixed;
            bottom: 5%;
            z-index: 100;
         }
			.timestamp {
				direction: rtl;
			}
			paper-card {
				margin: 4px;
				vertical-align: top;
			}
			paper-icon-item {
				--paper-item-icon-width: 32px;
				--paper-item-min-height: 1em;
			}
		</style>
	</template>`;

styleElement.register('style-element');

