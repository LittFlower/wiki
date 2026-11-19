/*\
title: $:/plugins/littflower/headless-graph-prerender/filters/graph-operators.js
type: application/javascript
module-type: filteroperator

Custom filter operators backed by the in-memory graph index.

  [hg-backlinks[0.5]]        explicit + implicit incoming links above a weight
  [hg-related[10]]           TF-IDF / tag-cooccurrence related notes, Top-N
  [hg-orphans[]]             nodes with in-degree and out-degree both zero
  [hg-path[Synthetic 0100]]  shortest undirected path (default depth 4)
  [hg-path:8[Target]]        override max depth
  [hg-path:directed[Target]] follow forward edges only
\*/
(function(){
"use strict";

var daemon = require("$:/plugins/littflower/headless-graph-prerender/startup/index-daemon.js");

function sourceTitles(source) {
	var titles = [];
	if (typeof source === "function") {
		source(function(tiddler, title) {
			if (title) {
				titles.push(title);
			}
		});
	}
	return titles;
}

function currentTiddler(options) {
	if (options && options.widget && typeof options.widget.getVariable === "function") {
		return options.widget.getVariable("currentTiddler") || "";
	}
	return "";
}

function sourceOrCurrent(source, options) {
	var titles = sourceTitles(source);
	if (!titles.length) {
		var current = currentTiddler(options);
		if (current) {
			titles.push(current);
		}
	}
	return titles;
}

function parseNumber(value, fallback) {
	var number = parseFloat(value);
	return isFinite(number) ? number : fallback;
}

function parseInteger(value, fallback) {
	var number = parseInt(value, 10);
	return isFinite(number) ? number : fallback;
}

function compareEntries(a, b) {
	return (b.weight - a.weight) || (a.title < b.title ? -1 : a.title > b.title ? 1 : 0);
}

/*
[hg-backlinks[weight]]

The operand is a minimum edge weight (default 0.5). Explicit links weigh 1.0,
transclusions 0.75 and tag memberships 0.5, so the default includes both
explicit and implicit incoming links.
*/
exports["hg-backlinks"] = function(source, operator, options) {
	var index = daemon.getIndex(options.wiki);
	var titles = sourceOrCurrent(source, options);
	var threshold = (operator.operand === undefined || operator.operand === "") ? 0.5 : parseNumber(operator.operand, 0.5);
	var seen = new Set();
	var merged = [];
	titles.forEach(function(title) {
		daemon.getBacklinks(index, title, threshold).forEach(function(entry) {
			if (!seen.has(entry.title)) {
				seen.add(entry.title);
				merged.push(entry);
			}
		});
	});
	merged.sort(compareEntries);
	return merged.map(function(entry) {
		return entry.title;
	});
};

/*
[hg-related[limit]]

TF-IDF cosine similarity plus tag Jaccard. Direct graph neighbors are excluded
so the result is a "potential" relation list. The operand is Top-N (default 10).
*/
exports["hg-related"] = function(source, operator, options) {
	var index = daemon.getIndex(options.wiki);
	var titles = sourceOrCurrent(source, options);
	var limit = parseInteger(operator.operand, 10);
	if (limit <= 0) {
		limit = 10;
	}
	var sourceSet = new Set(titles);
	var scores = new Map();
	titles.forEach(function(title) {
		daemon.computeRelated(index, title, { limit: limit }).forEach(function(entry) {
			if (sourceSet.has(entry.title)) {
				return;
			}
			if (entry.score > (scores.get(entry.title) || 0)) {
				scores.set(entry.title, entry.score);
			}
		});
	});
	return Array.from(scores.entries())
		.sort(function(a, b) {
			return (b[1] - a[1]) || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
		})
		.slice(0, limit)
		.map(function(entry) {
			return entry[0];
		});
};

/*
[hg-orphans[]]

With a source, the operator checks only those titles. Without a source it
checks every indexed non-system tiddler.
*/
exports["hg-orphans"] = function(source, operator, options) {
	var index = daemon.getIndex(options.wiki);
	var candidates = sourceTitles(source);
	return daemon.getOrphans(index, candidates.length ? candidates : null);
};

/*
[hg-path[Target]]
[hg-path:6[Target]]
[hg-path:directed[Target]]

Breadth-first search over the graph. Undirected by default because "how are
these two notes connected" is usually an undirected question. The default max
depth is 4 edges; numeric suffixes override it (capped at 12 by the daemon).
Returned titles include both endpoints.
*/
exports["hg-path"] = function(source, operator, options) {
	var index = daemon.getIndex(options.wiki);
	var target = operator.operand;
	if (!target) {
		return [];
	}
	var maxDepth = 4;
	var directed = false;
	String(operator.suffix || "").split(":").forEach(function(part) {
		if (part === "directed") {
			directed = true;
		} else if (/^\d+$/.test(part)) {
			maxDepth = parseInt(part, 10);
		}
	});
	var starts = sourceOrCurrent(source, options);
	for (var i = 0; i < starts.length; i++) {
		var path = daemon.findPath(index, starts[i], target, {
			maxDepth: maxDepth,
			directed: directed
		});
		if (path.length) {
			return path;
		}
	}
	return [];
};

})();
