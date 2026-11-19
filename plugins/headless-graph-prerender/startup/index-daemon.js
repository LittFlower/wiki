/*\
title: $:/plugins/littflower/headless-graph-prerender/startup/index-daemon.js
type: application/javascript
module-type: startup

Incremental knowledge-graph index daemon.

The index is intentionally kept in memory and shared by the filter operators,
the prerender command and the backlink panel widget:

  forward   Map<source, Map<target, weight>>
  backlinks Map<target, Map<source, weight>>
  terms     Map<term, Map<title, tf>>
  docs      Map<title, {tags, links, terms}>

Weights used by this demo:
  1.00  explicit wikilink / $link widget
  0.75  transclusion ({{Target}} / $transclude)
  0.50  tag membership

The 300ms debounce and the incremental update path are the interesting part of
this prototype; see the demo/ directory for a reproducible benchmark.
\*/
(function(){
"use strict";

var DEBOUNCE_MS = 300;
var EXPLICIT_WEIGHT = 1.0;
var TRANSCLUDE_WEIGHT = 0.75;
var TAG_WEIGHT = 0.5;
var SYSTEM_PREFIX = "$:/";
var MAX_TERMS_PER_DOC = 400;
var MAX_PATH_DEPTH = 12;

var state = {
	wiki: null,
	index: null,
	pending: Object.create(null),
	timer: null,
	lastBuildMs: 0,
	lastFlushMs: 0,
	flushCount: 0
};

function now() {
	return (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
}

function isIndexableTitle(title) {
	return typeof title === "string" && title.length > 0 && title.indexOf(SYSTEM_PREFIX) !== 0;
}

function createIndex() {
	return {
		version: 0,
		forward: new Map(),
		backlinks: new Map(),
		terms: new Map(),
		docs: new Map(),
		parseErrors: 0,
		buildMs: 0,
		builtAt: 0
	};
}

function getOrCreate(map, key) {
	var value = map.get(key);
	if (!value) {
		value = new Map();
		map.set(key, value);
	}
	return value;
}

function addEdge(index, source, target, weight) {
	var outgoing = getOrCreate(index.forward, source);
	var previousOut = outgoing.get(target) || 0;
	if (weight > previousOut) {
		outgoing.set(target, weight);
	}
	var incoming = getOrCreate(index.backlinks, target);
	var previousIn = incoming.get(source) || 0;
	if (weight > previousIn) {
		incoming.set(source, weight);
	}
}

function removeEdge(index, source, target) {
	var outgoing = index.forward.get(source);
	if (outgoing) {
		outgoing.delete(target);
		if (!outgoing.size) {
			index.forward.delete(source);
		}
	}
	var incoming = index.backlinks.get(target);
	if (incoming) {
		incoming.delete(source);
		if (!incoming.size) {
			index.backlinks.delete(target);
		}
	}
}

function attributeValue(attribute) {
	if (!attribute) {
		return "";
	}
	if (typeof attribute === "string") {
		return attribute;
	}
	return typeof attribute.value === "string" ? attribute.value : "";
}

function normalizeTarget(raw) {
	var target = String(raw || "").trim();
	if (!target) {
		return null;
	}
	if (/^(?:https?:|mailto:|ftp:|file:|data:|javascript:|\/\/)/i.test(target)) {
		return null;
	}
	if (target.charAt(0) === "#" || target.indexOf("$(") !== -1) {
		return null;
	}
	// Text references such as [[Title!!field]] only link to Title.
	var fieldPos = target.indexOf("!!");
	if (fieldPos > 0) {
		target = target.substring(0, fieldPos).trim();
	}
	return isIndexableTitle(target) ? target : null;
}

function walkTree(node, visit) {
	if (!node || typeof node !== "object") {
		return;
	}
	if (Array.isArray(node)) {
		for (var a = 0; a < node.length; a++) {
			walkTree(node[a], visit);
		}
		return;
	}
	visit(node);
	if (node.children) {
		for (var c = 0; c < node.children.length; c++) {
			walkTree(node.children[c], visit);
		}
	}
}

/*
Extract static link edges from the TiddlyWiki parse tree. This deliberately does
not evaluate macros or filters: the point of the demo is a cheap headless pass.
*/
function extractLinks(wiki, title) {
	var links = new Map();
	var tree;
	try {
		tree = wiki.parseTiddler(title);
	} catch (e) {
		return links;
	}
	if (!tree || !tree.tree) {
		return links;
	}
	walkTree(tree.tree, function(node) {
		var target = null;
		var weight = 0;
		if (node.type === "link" && node.attributes) {
			target = normalizeTarget(attributeValue(node.attributes.to));
			weight = EXPLICIT_WEIGHT;
		} else if (node.type === "tiddler" && node.attributes) {
			target = normalizeTarget(attributeValue(node.attributes.tiddler));
			weight = TRANSCLUDE_WEIGHT;
		} else if (node.type === "transclude" && node.attributes) {
			target = normalizeTarget(attributeValue(node.attributes.tiddler || node.attributes["$tiddler"]));
			weight = TRANSCLUDE_WEIGHT;
		}
		if (target && target !== title) {
			var previous = links.get(target) || 0;
			if (weight > previous) {
				links.set(target, weight);
			}
		}
	});
	return links;
}

function getTags(tiddler) {
	var tags = new Set();
	var raw = tiddler.fields.tags;
	if (Array.isArray(raw)) {
		for (var i = 0; i < raw.length; i++) {
			var tag = String(raw[i]).trim();
			if (tag) {
				tags.add(tag);
			}
		}
	} else if (typeof raw === "string") {
		raw.split(/\s+/).forEach(function(entry) {
			var tag = entry.trim();
			if (tag.charAt(0) === "[" && tag.charAt(tag.length - 1) === "]") {
				tag = tag.substring(1, tag.length - 1);
			}
			if (tag) {
				tags.add(tag);
			}
		});
	}
	return tags;
}

var LATIN_RE = /[a-z][a-z0-9_+.#-]{1,}/g;
var CJK_RE = /[㐀-䶿一-鿿豈-﫿぀-ヿ가-힯]+/g;
var EN_STOP = Object.create(null);
[
	"the","and","for","with","that","this","from","are","was","were","has","have",
	"had","not","but","you","your","can","will","would","could","should","into",
	"when","then","than","they","them","their","its","our","out","all","any","use",
	"using","used","one","two","also","more","most","some","such","only","other",
	"over","under","about","after","before","between","because","while","where",
	"what","which","who","how","why","https","http","www","com","org"
].forEach(function(word) {
	EN_STOP[word] = true;
});
var CJK_STOP = Object.create(null);
[
	"的了","和与","与及","是在","是有","这个","那个","一个","我们","你们","他们",
	"可以","没有","不是","就是","因为","所以","如果","但是","而且","以及","对于",
	"通过","进行","使用","需要","已经","能够","时候","问题","东西","这样","那样",
	"自己","什么","怎么","为了","其中","这些","那些","一种","相关","如下","以上","以下"
].forEach(function(term) {
	CJK_STOP[term] = true;
});

function addTerm(counts, term) {
	if (counts.size >= MAX_TERMS_PER_DOC && !counts.has(term)) {
		return;
	}
	counts.set(term, (counts.get(term) || 0) + 1);
}

/*
A deliberately small tokenizer:
  - Latin words, lower-cased, length >= 2
  - CJK bigrams (unigram when the run is one character)
This handles both English and Chinese notes without shipping a dictionary.
*/
function tokenize(text) {
	var counts = new Map();
	var source = String(text || "").toLowerCase();
	source = source.replace(/<[^>]+>/g, " ").replace(/https?:\/\/[^\s\]]+/g, " ").replace(/[\[\]{}|$]/g, " ");
	var match;
	LATIN_RE.lastIndex = 0;
	while ((match = LATIN_RE.exec(source))) {
		var word = match[0];
		if (word.length >= 2 && !EN_STOP[word]) {
			addTerm(counts, word);
		}
	}
	CJK_RE.lastIndex = 0;
	while ((match = CJK_RE.exec(source))) {
		var run = match[0];
		if (run.length === 1) {
			addTerm(counts, run);
		} else {
			for (var i = 0; i < run.length - 1; i++) {
				var bigram = run.substr(i, 2);
				if (!CJK_STOP[bigram]) {
					addTerm(counts, bigram);
				}
			}
		}
	}
	return counts;
}

function indexTiddler(index, tiddler, wiki) {
	var title = tiddler.fields.title;
	if (!isIndexableTitle(title)) {
		return;
	}
	unindexTiddler(index, title);
	var links = extractLinks(wiki, title);
	var tags = getTags(tiddler);
	tags.forEach(function(tag) {
		if (!isIndexableTitle(tag)) {
			return;
		}
		var previous = links.get(tag) || 0;
		if (TAG_WEIGHT > previous) {
			links.set(tag, TAG_WEIGHT);
		}
	});
	var terms = tokenize(tiddler.fields.text || "");
	var doc = {
		title: title,
		tags: tags,
		links: links,
		terms: terms
	};
	index.docs.set(title, doc);
	links.forEach(function(weight, target) {
		addEdge(index, title, target, weight);
	});
	terms.forEach(function(tf, term) {
		getOrCreate(index.terms, term).set(title, tf);
	});
}

function unindexTiddler(index, title) {
	var doc = index.docs.get(title);
	if (!doc) {
		return;
	}
	doc.links.forEach(function(weight, target) {
		removeEdge(index, title, target);
	});
	doc.terms.forEach(function(tf, term) {
		var postings = index.terms.get(term);
		if (!postings) {
			return;
		}
		postings.delete(title);
		if (!postings.size) {
			index.terms.delete(term);
		}
	});
	index.docs.delete(title);
}

function buildFullIndex(wiki) {
	var started = now();
	var index = createIndex();
	var titles = wiki.getTiddlers(); // TiddlyWiki returns non-system titles, sorted
	for (var i = 0; i < titles.length; i++) {
		var tiddler = wiki.getTiddler(titles[i]);
		if (tiddler) {
			indexTiddler(index, tiddler, wiki);
		}
	}
	index.version = 1;
	index.buildMs = now() - started;
	index.builtAt = Date.now();
	return index;
}

function getIndex(wiki) {
	if (!wiki) {
		wiki = $tw.wiki;
	}
	if (!state.index || state.wiki !== wiki) {
		state.wiki = wiki;
		state.index = buildFullIndex(wiki);
		state.lastBuildMs = state.index.buildMs;
	}
	return state.index;
}

function rebuild(wiki) {
	if (!wiki) {
		wiki = $tw.wiki;
	}
	cancelPending();
	state.wiki = wiki;
	state.index = buildFullIndex(wiki);
	state.lastBuildMs = state.index.buildMs;
	return state.index;
}

function getBacklinks(index, title, threshold) {
	var incoming = index.backlinks.get(title);
	var limit = (typeof threshold === "number" && isFinite(threshold)) ? threshold : 0.5;
	var results = [];
	if (!incoming) {
		return results;
	}
	incoming.forEach(function(weight, source) {
		if (weight >= limit) {
			results.push({ title: source, weight: weight });
		}
	});
	results.sort(function(a, b) {
		return (b.weight - a.weight) || (a.title < b.title ? -1 : a.title > b.title ? 1 : 0);
	});
	return results;
}

function getNeighbors(index, title, directed) {
	var neighbors = new Set();
	var outgoing = index.forward.get(title);
	if (outgoing) {
		outgoing.forEach(function(weight, target) {
			neighbors.add(target);
		});
	}
	if (!directed) {
		var incoming = index.backlinks.get(title);
		if (incoming) {
			incoming.forEach(function(weight, source) {
				neighbors.add(source);
			});
		}
	}
	return neighbors;
}

function termIdf(index, term) {
	var postings = index.terms.get(term);
	var df = postings ? postings.size : 0;
	return Math.log((index.docs.size + 1) / (df + 1)) + 1;
}

function buildVector(doc, idf) {
	var vector = new Map();
	var norm = 0;
	doc.terms.forEach(function(tf, term) {
		var weight = (1 + Math.log(tf)) * idf(term);
		vector.set(term, weight);
		norm += weight * weight;
	});
	return { vector: vector, norm: Math.sqrt(norm) || 1 };
}

function jaccard(a, b) {
	if (!a.size || !b.size) {
		return 0;
	}
	var smaller = a.size <= b.size ? a : b;
	var larger = a.size <= b.size ? b : a;
	var intersection = 0;
	smaller.forEach(function(value) {
		if (larger.has(value)) {
			intersection++;
		}
	});
	var union = a.size + b.size - intersection;
	return union ? intersection / union : 0;
}

/*
TF-IDF cosine similarity plus tag Jaccard. Direct graph neighbors are excluded
by default so the result is "potential" related notes rather than a second copy
of the backlink list.
*/
function computeRelated(index, title, options) {
	options = options || {};
	var limit = options.limit;
	if (typeof limit !== "number" || !isFinite(limit) || limit <= 0) {
		limit = 10;
	}
	var doc = index.docs.get(title);
	if (!doc) {
		return [];
	}
	var excludeNeighbors = options.excludeNeighbors !== false;
	var neighbors = excludeNeighbors ? getNeighbors(index, title, false) : new Set();
	var idfCache = new Map();
	function idf(term) {
		var value = idfCache.get(term);
		if (value === undefined) {
			value = termIdf(index, term);
			idfCache.set(term, value);
		}
		return value;
	}
	var sourceVector = buildVector(doc, idf);
	var scores = new Map();
	sourceVector.vector.forEach(function(weightA, term) {
		var postings = index.terms.get(term);
		if (!postings) {
			return;
		}
		postings.forEach(function(tfB, otherTitle) {
			if (otherTitle === title || neighbors.has(otherTitle)) {
				return;
			}
			var weightB = (1 + Math.log(tfB)) * idf(term);
			scores.set(otherTitle, (scores.get(otherTitle) || 0) + weightA * weightB);
		});
	});
	var results = [];
	scores.forEach(function(dot, otherTitle) {
		var otherDoc = index.docs.get(otherTitle);
		if (!otherDoc) {
			return;
		}
		var otherVector = buildVector(otherDoc, idf);
		var cosine = dot / (sourceVector.norm * otherVector.norm);
		var tagScore = jaccard(doc.tags, otherDoc.tags);
		var score = 0.75 * cosine + 0.25 * tagScore;
		if (score > 0) {
			results.push({
				title: otherTitle,
				score: score,
				cosine: cosine,
				tagScore: tagScore
			});
		}
	});
	results.sort(function(a, b) {
		return (b.score - a.score) || (a.title < b.title ? -1 : a.title > b.title ? 1 : 0);
	});
	return results.slice(0, limit);
}

function getOrphans(index, candidates) {
	var titles = (candidates && candidates.length) ? candidates : Array.from(index.docs.keys());
	var results = [];
	var seen = new Set();
	for (var i = 0; i < titles.length; i++) {
		var title = titles[i];
		if (seen.has(title) || !index.docs.has(title)) {
			continue;
		}
		seen.add(title);
		var outgoing = index.forward.get(title);
		var incoming = index.backlinks.get(title);
		var outDegree = outgoing ? outgoing.size : 0;
		var inDegree = incoming ? incoming.size : 0;
		if (outDegree === 0 && inDegree === 0) {
			results.push(title);
		}
	}
	results.sort();
	return results;
}

function findPath(index, from, to, options) {
	options = options || {};
	var maxDepth = options.maxDepth || 4;
	if (maxDepth < 1) {
		maxDepth = 1;
	}
	if (maxDepth > MAX_PATH_DEPTH) {
		maxDepth = MAX_PATH_DEPTH;
	}
	var directed = !!options.directed;
	if (!from || !to || !index.docs.has(from) || !index.docs.has(to)) {
		return [];
	}
	if (from === to) {
		return [from];
	}
	var queue = [{ title: from, depth: 0 }];
	var visited = new Set([from]);
	var parents = new Map();
	var head = 0;
	while (head < queue.length) {
		var current = queue[head++];
		if (current.depth >= maxDepth) {
			continue;
		}
		var neighbors = Array.from(getNeighbors(index, current.title, directed)).sort();
		for (var i = 0; i < neighbors.length; i++) {
			var next = neighbors[i];
			if (visited.has(next) || !index.docs.has(next)) {
				continue;
			}
			visited.add(next);
			parents.set(next, current.title);
			if (next === to) {
				var path = [to];
				var node = to;
				while (parents.has(node)) {
					node = parents.get(node);
					path.unshift(node);
				}
				return path;
			}
			queue.push({ title: next, depth: current.depth + 1 });
		}
	}
	return [];
}

function updateTiddler(wiki, title) {
	var index = getIndex(wiki);
	var tiddler = wiki && wiki.getTiddler(title);
	var started = now();
	if (tiddler && isIndexableTitle(title)) {
		indexTiddler(index, tiddler, wiki);
	} else {
		unindexTiddler(index, title);
	}
	index.version++;
	state.lastFlushMs = now() - started;
	return state.lastFlushMs;
}

function scheduleFlush() {
	if (state.timer) {
		clearTimeout(state.timer);
	}
	state.timer = setTimeout(function() {
		state.timer = null;
		flush();
	}, DEBOUNCE_MS);
}

function flush() {
	if (state.timer) {
		clearTimeout(state.timer);
		state.timer = null;
	}
	var wiki = state.wiki || $tw.wiki;
	if (!wiki) {
		return null;
	}
	var index = getIndex(wiki);
	var started = now();
	var pending = state.pending;
	state.pending = Object.create(null);
	Object.keys(pending).forEach(function(title) {
		var tiddler = pending[title] === "delete" ? null : wiki.getTiddler(title);
		if (tiddler && isIndexableTitle(title)) {
			indexTiddler(index, tiddler, wiki);
		} else {
			unindexTiddler(index, title);
		}
	});
	index.version++;
	state.lastFlushMs = now() - started;
	state.flushCount++;
	if (typeof wiki.dispatchEvent === "function") {
		wiki.dispatchEvent("hg-index-updated", {
			version: index.version,
			elapsedMs: state.lastFlushMs
		});
	}
	return state.lastFlushMs;
}

function cancelPending() {
	if (state.timer) {
		clearTimeout(state.timer);
		state.timer = null;
	}
	state.pending = Object.create(null);
}

function onWikiChange(changedTiddlers) {
	var hasPending = false;
	Object.keys(changedTiddlers || {}).forEach(function(title) {
		if (!isIndexableTitle(title)) {
			return;
		}
		state.pending[title] = (changedTiddlers[title] && changedTiddlers[title].deleted) ? "delete" : "update";
		hasPending = true;
	});
	if (hasPending) {
		scheduleFlush();
	}
}

function getStats() {
	var index = state.index;
	if (!index) {
		return { ready: false };
	}
	var edges = 0;
	index.forward.forEach(function(targets) {
		edges += targets.size;
	});
	return {
		ready: true,
		nodes: index.docs.size,
		edges: edges,
		terms: index.terms.size,
		version: index.version,
		buildMs: index.buildMs,
		lastFlushMs: state.lastFlushMs,
		flushCount: state.flushCount,
		pending: Object.keys(state.pending).length
	};
}

exports.name = "hg-index-daemon";
exports.platforms = ["browser", "node"];
exports.after = ["load-modules"];
exports.synchronous = true;

exports.startup = function() {
	var wiki = $tw.wiki;
	state.wiki = wiki;
	var started = now();
	state.index = buildFullIndex(wiki);
	state.lastBuildMs = now() - started;
	wiki.addEventListener("change", onWikiChange);
	// Convenient handle for the console and the demo scripts.
	$tw.hgGraph = {
		getIndex: function() { return getIndex(wiki); },
		rebuild: function() { return rebuild(wiki); },
		getStats: getStats,
		flush: flush,
		cancelPending: cancelPending,
		updateTiddler: function(title) { return updateTiddler(wiki, title); },
		getBacklinks: function(title, threshold) { return getBacklinks(getIndex(wiki), title, threshold); },
		getRelated: function(title, limit) { return computeRelated(getIndex(wiki), title, { limit: limit }); },
		getOrphans: function(candidates) { return getOrphans(getIndex(wiki), candidates); },
		findPath: function(from, to, options) { return findPath(getIndex(wiki), from, to, options); },
		tokenize: tokenize
	};
};

exports.buildFullIndex = buildFullIndex;
exports.createIndex = createIndex;
exports.indexTiddler = indexTiddler;
exports.unindexTiddler = unindexTiddler;
exports.getIndex = getIndex;
exports.rebuild = rebuild;
exports.updateTiddler = updateTiddler;
exports.flush = flush;
exports.cancelPending = cancelPending;
exports.getStats = getStats;
exports.getBacklinks = getBacklinks;
exports.computeRelated = computeRelated;
exports.getOrphans = getOrphans;
exports.findPath = findPath;
exports.tokenize = tokenize;
exports.isIndexableTitle = isIndexableTitle;
exports.DEBOUNCE_MS = DEBOUNCE_MS;

})();
