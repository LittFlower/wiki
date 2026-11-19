/*\
title: $:/plugins/littflower/headless-graph-prerender/commands/prerender-graph.js
type: application/javascript
module-type: command

Build the full graph index headlessly and serialise it into
$:/temp/static-index/.

  tiddlywiki <wiki> --prerender-graph

Outputs:
  $:/temp/static-index/summary         run metadata + timings
  $:/temp/static-index/graph.json      nodes and weighted edges
  $:/temp/static-index/terms.json      term -> [[title, tf], ...]
  $:/temp/static-index/html/<title>    static per-tiddler HTML fragment
\*/
(function(){
"use strict";

var daemon = require("$:/plugins/littflower/headless-graph-prerender/startup/index-daemon.js");

var OUTPUT_PREFIX = "$:/temp/static-index/";

function escapeHtml(value) {
	return $tw.utils.htmlEncode(String(value === undefined ? "" : value));
}

function linkHtml(title) {
	return '<a class="hg-link" href="#' + escapeHtml(encodeURIComponent(title)) + '">' + escapeHtml(title) + "</a>";
}

function buildFragment(index, title) {
	var doc = index.docs.get(title);
	var tags = doc ? Array.from(doc.tags).sort() : [];
	var backlinks = daemon.getBacklinks(index, title, 0.5);
	var outgoing = index.forward.get(title);
	var outLinks = [];
	if (outgoing) {
		outgoing.forEach(function(weight, target) {
			outLinks.push({ title: target, weight: weight });
		});
	}
	outLinks.sort(function(a, b) {
		return (b.weight - a.weight) || (a.title < b.title ? -1 : a.title > b.title ? 1 : 0);
	});
	var html = [
		'<article class="hg-fragment" data-title="' + escapeHtml(title) + '">',
		"<h3>" + linkHtml(title) + "</h3>"
	];
	if (tags.length) {
		html.push('<p class="hg-tags">标签：' + tags.map(function(tag) {
			return '<span class="hg-tag">' + escapeHtml(tag) + "</span>";
		}).join(" ") + "</p>");
	}
	html.push('<div class="hg-section-title">入链</div>');
	if (backlinks.length) {
		html.push('<ul class="hg-list">' + backlinks.map(function(entry) {
			return "<li>" + linkHtml(entry.title) + '<span class="hg-weight">' + entry.weight.toFixed(2) + "</span></li>";
		}).join("") + "</ul>");
	} else {
		html.push('<p class="hg-empty">没有入链。</p>');
	}
	html.push('<div class="hg-section-title">出链</div>');
	if (outLinks.length) {
		html.push('<ul class="hg-list">' + outLinks.map(function(entry) {
			return "<li>" + linkHtml(entry.title) + '<span class="hg-weight">' + entry.weight.toFixed(2) + "</span></li>";
		}).join("") + "</ul>");
	} else {
		html.push('<p class="hg-empty">没有出链。</p>');
	}
	html.push("</article>");
	return html.join("");
}

exports.info = {
	name: "prerender-graph",
	synchronous: true
};

var Command = function(params, commander) {
	this.params = params;
	this.commander = commander;
};

Command.prototype.execute = function() {
	var output = this.commander && this.commander.streams && this.commander.streams.output;
	var write = function(text) {
		if (output && output.write) {
			output.write(text);
		} else if (typeof console !== "undefined") {
			console.log(text);
		}
	};
	if (!$tw.fakeDocument) {
		return "prerender-graph must run under Node with $tw.fakeDocument";
	}
	var wiki = $tw.wiki;
	var started = Date.now();
	var index = daemon.buildFullIndex(wiki);
	var elapsed = Date.now() - started;

	var nodes = [];
	index.docs.forEach(function(doc, title) {
		var outgoing = index.forward.get(title);
		var incoming = index.backlinks.get(title);
		nodes.push({
			title: title,
			tags: Array.from(doc.tags),
			outDegree: outgoing ? outgoing.size : 0,
			inDegree: incoming ? incoming.size : 0
		});
	});
	nodes.sort(function(a, b) {
		return a.title < b.title ? -1 : a.title > b.title ? 1 : 0;
	});

	var edges = [];
	index.forward.forEach(function(targets, source) {
		targets.forEach(function(weight, target) {
			edges.push([source, target, weight]);
		});
	});
	edges.sort(function(a, b) {
		return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0;
	});

	var terms = Object.create(null);
	index.terms.forEach(function(postings, term) {
		var entries = [];
		postings.forEach(function(tf, title) {
			entries.push([title, tf]);
		});
		terms[term] = entries;
	});

	var summary = {
		generatedAt: new Date().toISOString(),
		indexMs: elapsed,
		nodes: nodes.length,
		edges: edges.length,
		terms: index.terms.size,
		exportedFragments: 0,
		budgetMs: 1500
	};

	wiki.addTiddler(new $tw.Tiddler({
		title: OUTPUT_PREFIX + "graph.json",
		type: "application/json",
		text: JSON.stringify({ summary: summary, nodes: nodes, edges: edges })
	}));
	wiki.addTiddler(new $tw.Tiddler({
		title: OUTPUT_PREFIX + "terms.json",
		type: "application/json",
		text: JSON.stringify(terms)
	}));

	var fragments = 0;
	index.docs.forEach(function(doc, title) {
		wiki.addTiddler(new $tw.Tiddler({
			title: OUTPUT_PREFIX + "html/" + encodeURIComponent(title),
			type: "text/html",
			text: buildFragment(index, title)
		}));
		fragments++;
	});

	summary.exportedFragments = fragments;
	summary.totalMs = Date.now() - started;
	wiki.addTiddler(new $tw.Tiddler({
		title: OUTPUT_PREFIX + "summary",
		type: "application/json",
		text: JSON.stringify(summary)
	}));

	daemon.cancelPending();
	write("prerender-graph: " + summary.nodes + " nodes, " + summary.edges + " edges, " +
		summary.terms + " terms, " + fragments + " html fragments in " + summary.totalMs +
		"ms (index " + elapsed + "ms, budget " + summary.budgetMs + "ms)\n");
	return null;
};

exports.Command = Command;

})();
