/*
 * Node unit tests for the headless-graph-prerender prototype.
 *
 *   npm run test:graph
 */
"use strict";

const { test, before } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const repoRoot = path.resolve(__dirname, "..");
process.env.TIDDLYWIKI_PLUGIN_PATH = path.join(repoRoot, "plugins");

const $tw = require("tiddlywiki").TiddlyWiki();
$tw.boot.argv = [path.join(repoRoot, "demo/headless-graph-prerender/wiki")];
$tw.boot.boot();

const daemon = $tw.modules.execute("$:/plugins/littflower/headless-graph-prerender/startup/index-daemon.js");
const commandModule = $tw.modules.execute("$:/plugins/littflower/headless-graph-prerender/commands/prerender-graph.js");

function add(title, text, tags) {
	$tw.wiki.addTiddler(new $tw.Tiddler({
		title,
		text,
		tags: tags || []
	}));
}

before(() => {
	add("Alpha", "Alpha links [[Beta]] and [[Gamma]].", ["topic"]);
	add("Beta", "Beta links [[Alpha]].", ["topic"]);
	add("Gamma", "Gamma links [[Delta]].", ["topic"]);
	add("Delta", "Delta is a leaf.", []);
	add("Island", "No links, no tags.", []);
	add("topic", "A tag tiddler.", []);
	add("Vector A", "quasar nebula flux capacitor tachyon", []);
	add("Vector B", "quasar nebula flux capacitor tachyon", []);
	add("Vector C", "quasar nebula unrelated filler", []);
	add("One", "[[Two]]", []);
	add("Two", "[[Three]]", []);
	add("Three", "[[Four]]", []);
	add("Four", "", []);
	$tw.wiki.clearTiddlerEventQueue();
	daemon.cancelPending();
	daemon.rebuild($tw.wiki);
});

test("explicit backlinks carry weight 1.0 and tag backlinks carry 0.5", () => {
	const index = daemon.rebuild($tw.wiki);
	const alphaBacklinks = daemon.getBacklinks(index, "Alpha", 0.5);
	const beta = alphaBacklinks.find((entry) => entry.title === "Beta");
	assert.ok(beta, "Beta should be an explicit backlink of Alpha");
	assert.equal(beta.weight, 1.0);

	const topicBacklinks = daemon.getBacklinks(index, "topic", 0.5);
	assert.ok(topicBacklinks.some((entry) => entry.title === "Alpha"));
	assert.equal(topicBacklinks.find((entry) => entry.title === "Alpha").weight, 0.5);
});

test("hg-backlinks[] filter resolves through the index", () => {
	const result = $tw.wiki.filterTiddlers("[[Alpha]hg-backlinks[0.5]]");
	assert.ok(result.includes("Beta"), "filter should find Beta");
	assert.ok(!result.includes("Gamma"), "Gamma links to Delta, not Alpha");
});

test("hg-orphans[] returns only zero-degree nodes", () => {
	const index = daemon.rebuild($tw.wiki);
	const orphans = daemon.getOrphans(index, ["Alpha", "Island", "Delta"]);
	assert.deepEqual(Array.from(orphans), ["Island"]);
	const fromFilter = $tw.wiki.filterTiddlers("[all[tiddlers]!is[system]hg-orphans[]]");
	assert.ok(fromFilter.includes("Island"));
	assert.ok(!fromFilter.includes("Alpha"));
});

test("hg-related[] ranks shared-term notes above unrelated ones", () => {
	const index = daemon.rebuild($tw.wiki);
	const related = daemon.computeRelated(index, "Vector A", { limit: 5 });
	const titles = related.map((entry) => entry.title);
	assert.ok(titles.includes("Vector B"), "Vector B shares every term");
	assert.ok(!titles.includes("Vector A"), "self must be excluded");
});

test("hg-path[] finds the shortest path and respects the depth cap", () => {
	const index = daemon.rebuild($tw.wiki);
	assert.deepEqual(Array.from(daemon.findPath(index, "One", "Four", { maxDepth: 4 })), ["One", "Two", "Three", "Four"]);
	assert.deepEqual(Array.from(daemon.findPath(index, "One", "Four", { maxDepth: 2 })), []);
	const filtered = $tw.wiki.filterTiddlers("[[One]hg-path[Three]]");
	assert.deepEqual(Array.from(filtered), ["One", "Two", "Three"]);
});

test("incremental update adds and removes a backlink", () => {
	const index = daemon.rebuild($tw.wiki);
	add("Fresh", "[[Alpha]]", []);
	$tw.wiki.clearTiddlerEventQueue();
	daemon.updateTiddler($tw.wiki, "Fresh");
	assert.ok(daemon.getBacklinks(index, "Alpha", 0.5).some((entry) => entry.title === "Fresh"));

	$tw.wiki.deleteTiddler("Fresh");
	$tw.wiki.clearTiddlerEventQueue();
	daemon.updateTiddler($tw.wiki, "Fresh");
	assert.ok(!daemon.getBacklinks(index, "Alpha", 0.5).some((entry) => entry.title === "Fresh"));
});

test("--prerender-graph serialises the static index", () => {
	const command = new commandModule.Command([], {
		streams: { output: { write() {} }, error: process.stderr }
	});
	const error = command.execute();
	assert.equal(error, null);
	const summary = $tw.wiki.getTiddler("$:/temp/static-index/summary");
	assert.ok(summary, "summary tiddler should exist");
	const parsed = JSON.parse(summary.fields.text);
	assert.ok(parsed.nodes >= 13);
	assert.ok(parsed.exportedFragments === parsed.nodes);
	assert.ok($tw.wiki.getTiddler("$:/temp/static-index/graph.json"));
	assert.ok($tw.wiki.getTiddler("$:/temp/static-index/html/Alpha"));
});
