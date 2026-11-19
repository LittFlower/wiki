/*\
title: $:/plugins/littflower/headless-graph-prerender/widgets/backlink-panel.js
type: application/javascript
module-type: widget

Lightweight related-context card.

Usage:
  <$backlink-panel/>
  <$backlink-panel tiddler="Some Note" limit="8"/>
  <$backlink-panel mode="orphans" limit="40"/>

The widget renders from the same in-memory index as the filter operators and
redraws only its own DOM node after the daemon flushes (300ms debounce).
\*/
(function(){
"use strict";

var Widget = require("$:/core/modules/widgets/widget.js").widget;
var daemon = require("$:/plugins/littflower/headless-graph-prerender/startup/index-daemon.js");

function escapeHtml(value) {
	return $tw.utils.htmlEncode(String(value === undefined ? "" : value));
}

function linkHtml(title) {
	return '<a class="hg-link" href="#' + escapeHtml(encodeURIComponent(title)) + '">' + escapeHtml(title) + "</a>";
}

function listHtml(entries, renderEntry, emptyText) {
	if (!entries.length) {
		return '<p class="hg-empty">' + escapeHtml(emptyText) + "</p>";
	}
	var html = ['<ul class="hg-list">'];
	entries.forEach(function(entry) {
		html.push("<li>" + renderEntry(entry) + "</li>");
	});
	html.push("</ul>");
	return html.join("");
}

/*
Pure HTML builder, exported as a static helper so it can be unit-tested
without a live DOM.
*/
function buildPanelHtml(index, title, options) {
	options = options || {};
	var limit = options.limit || 8;
	var mode = options.mode || "context";
	if (mode === "orphans") {
		var allOrphans = daemon.getOrphans(index, null);
		var shown = allOrphans.slice(0, limit);
		return [
			'<div class="hg-panel-head">孤岛节点',
			'<span class="hg-count">' + allOrphans.length + "</span></div>",
			'<p class="hg-hint">入度与出度均为 0 的条目。此视图只读，不会删除任何数据。</p>',
			listHtml(shown, function(entry) {
				return linkHtml(entry);
			}, "没有孤岛节点。"),
			allOrphans.length > shown.length ? '<p class="hg-more">仅显示前 ' + shown.length + " 个</p>" : ""
		].join("");
	}
	var backlinks = daemon.getBacklinks(index, title, 0.5);
	var related = daemon.computeRelated(index, title, { limit: limit });
	return [
		'<div class="hg-panel-head">关联上下文',
		'<span class="hg-count">入链 ' + backlinks.length + " · 关联 " + related.length + "</span></div>",
		'<div class="hg-section"><div class="hg-section-title">入链</div>',
		listHtml(backlinks, function(entry) {
			return linkHtml(entry.title) + '<span class="hg-weight">' + entry.weight.toFixed(2) + "</span>";
		}, "没有入链。"),
		"</div>",
		'<div class="hg-section"><div class="hg-section-title">潜在关联</div>',
		listHtml(related, function(entry) {
			return linkHtml(entry.title) + '<span class="hg-weight">' + entry.score.toFixed(3) + "</span>";
		}, "没有足够相似的条目。"),
		"</div>"
	].join("");
}

var BacklinkPanelWidget = function(parseTreeNode, options) {
	this.initialise(parseTreeNode, options);
};

BacklinkPanelWidget.prototype = new Widget();

BacklinkPanelWidget.prototype.execute = function() {
	this.tiddlerTitle = this.getAttribute("tiddler", this.getVariable("currentTiddler"));
	this.limit = parseInt(this.getAttribute("limit", "8"), 10) || 8;
	this.mode = this.getAttribute("mode", "context");
	this.index = daemon.getIndex(this.wiki);
	this.lastVersion = this.index.version;
};

BacklinkPanelWidget.prototype.buildHtml = function() {
	this.index = daemon.getIndex(this.wiki);
	return buildPanelHtml(this.index, this.tiddlerTitle, {
		limit: this.limit,
		mode: this.mode
	});
};

BacklinkPanelWidget.prototype.render = function(parent, nextSibling) {
	this.parentDomNode = parent;
	this.computeAttributes();
	this.execute();
	this.domNode = this.document.createElement("div");
	this.domNode.className = "hg-backlink-panel hg-mode-" + this.mode;
	this.lastHtml = this.buildHtml();
	this.domNode.innerHTML = this.lastHtml;
	parent.insertBefore(this.domNode, nextSibling);
	this.domNodes.push(this.domNode);
	this.listenForIndexUpdates();
};

BacklinkPanelWidget.prototype.listenForIndexUpdates = function() {
	var self = this;
	if (this.indexListener) {
		this.wiki.removeEventListener("hg-index-updated", this.indexListener);
	}
	this.indexListener = function() {
		if (self.domNode && self.domNode.parentNode) {
			self.updateDom();
		} else {
			self.wiki.removeEventListener("hg-index-updated", self.indexListener);
			self.indexListener = null;
		}
	};
	this.wiki.addEventListener("hg-index-updated", this.indexListener);
};

/*
Only this panel is redrawn; returning true tells TiddlyWiki that the widget
handled the change itself.
*/
BacklinkPanelWidget.prototype.refresh = function(changedTiddlers) {
	var affected = false;
	Object.keys(changedTiddlers || {}).forEach(function(title) {
		if (title.indexOf("$:/") !== 0) {
			affected = true;
		}
	});
	if (affected) {
		this.scheduleRefresh();
	}
	return affected;
};

BacklinkPanelWidget.prototype.scheduleRefresh = function() {
	var self = this;
	if (this.refreshTimer) {
		clearTimeout(this.refreshTimer);
	}
	// Fallback for environments where the daemon event is missed. The daemon
	// itself flushes 300ms after the last change.
	this.refreshTimer = setTimeout(function() {
		self.refreshTimer = null;
		if (self.domNode && self.domNode.parentNode) {
			self.updateDom();
		}
	}, 360);
};

BacklinkPanelWidget.prototype.updateDom = function() {
	if (this.refreshTimer) {
		clearTimeout(this.refreshTimer);
		this.refreshTimer = null;
	}
	var html = this.buildHtml();
	if (html !== this.lastHtml) {
		this.lastHtml = html;
		this.domNode.innerHTML = html;
	}
	this.lastVersion = this.index.version;
};

BacklinkPanelWidget.prototype.removeChildDomNodes = function() {
	if (this.refreshTimer) {
		clearTimeout(this.refreshTimer);
		this.refreshTimer = null;
	}
	if (this.indexListener && this.wiki) {
		this.wiki.removeEventListener("hg-index-updated", this.indexListener);
		this.indexListener = null;
	}
	Widget.prototype.removeChildDomNodes.call(this);
};

BacklinkPanelWidget.buildPanelHtml = buildPanelHtml;

exports["backlink-panel"] = BacklinkPanelWidget;
exports["hg-backlink-panel"] = BacklinkPanelWidget;

})();
