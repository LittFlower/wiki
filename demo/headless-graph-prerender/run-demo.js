#!/usr/bin/env node
/*
 * headless-graph-prerender demo
 *
 *   npm run demo:graph
 *
 * Boots the tiny demo wiki, seeds 1,200 synthetic notes, rebuilds the graph
 * index, runs the custom filters, measures a single incremental update, then
 * executes the --prerender-graph command in-process.
 *
 * This is a prototype measurement, not a CI benchmark: wall-clock numbers vary
 * with the machine and the Node/TiddlyWiki version.
 */
"use strict";

const path = require("path");

const repoRoot = path.resolve(__dirname, "..", "..");
const wikiDir = path.join(__dirname, "wiki");
process.env.TIDDLYWIKI_PLUGIN_PATH = path.join(repoRoot, "plugins");

let $tw;
try {
	$tw = require("tiddlywiki").TiddlyWiki();
} catch (error) {
	console.error("找不到 tiddlywiki。请先在仓库根目录运行 npm install。");
	console.error(String(error && error.message ? error.message : error));
	process.exit(1);
}

$tw.boot.argv = [wikiDir];
$tw.boot.boot();

const daemon = $tw.modules.execute("$:/plugins/littflower/headless-graph-prerender/startup/index-daemon.js");
const commandModule = $tw.modules.execute("$:/plugins/littflower/headless-graph-prerender/commands/prerender-graph.js");

const NODE_COUNT = 1200;
const pad = (number) => String(number).padStart(4, "0");
const clock = () => (typeof performance !== "undefined" && performance.now ? performance.now() : Date.now());

function seedSyntheticNotes() {
	const paragraph =
		"图谱索引把 wiki 当作有向带权图。节点是条目，边是显式链接、反向链接、标签共现和词项倒排。" +
		"The headless pass builds an in-memory forward map, backlink map and term inverted index. ";
	for (let i = 0; i < NODE_COUNT; i++) {
		const title = "Synthetic " + pad(i);
		const links = [];
		if (i + 1 < NODE_COUNT) {
			links.push("[[" + "Synthetic " + pad(i + 1) + "]]");
		}
		if (i % 11 === 0) {
			links.push("[[Knowledge graph]]");
		}
		if (i > 0 && i % 7 === 0) {
			links.push("[[" + "Synthetic " + pad(i - 3) + "]]");
		}
		const tags = i % 5 === 0 ? ["synthetic-cluster"] : [];
		const uniqueTokens = [];
		for (let j = 0; j < 8; j++) {
			uniqueTokens.push("token" + pad(i) + "x" + j);
		}
		$tw.wiki.addTiddler(new $tw.Tiddler({
			title,
			tags,
			text: links.join(" ") + "\n\n" + paragraph.repeat(3) +
				"Synthetic node " + pad(i) + " keyword" + (i % 13) +
				" 图谱 索引 演示 关联 上下文 " + uniqueTokens.join(" ")
		}));
	}
	// Drop the queued change events so the demo's own seeding does not trigger
	// the daemon's debounce timer before we measure a clean rebuild.
	$tw.wiki.clearTiddlerEventQueue();
	daemon.cancelPending();
}

function time(label, fn) {
	const started = clock();
	const value = fn();
	return { ms: clock() - started, value };
}

seedSyntheticNotes();

const rebuild = time("rebuild", () => daemon.rebuild($tw.wiki));
const index = rebuild.value;
const stats = daemon.getStats();

const backlinks = $tw.wiki.filterTiddlers("[[Synthetic 0001]hg-backlinks[0.5]]");
const related = $tw.wiki.filterTiddlers("[[Synthetic 0001]hg-related[5]]");
const pathResult = $tw.wiki.filterTiddlers("[[Synthetic 0001]hg-path[Synthetic 0005]]");
const orphans = $tw.wiki.filterTiddlers("[all[tiddlers]!is[system]hg-orphans[]]");

const changedTitle = "Synthetic 0001";
$tw.wiki.addTiddler(new $tw.Tiddler({
	title: changedTitle,
	tags: ["synthetic-cluster", "demo-updated"],
	text: "[[Synthetic 0002]] [[Synthetic 0005]] [[Knowledge graph]] 刚刚编辑过的条目 增量 索引 更新"
}));
$tw.wiki.clearTiddlerEventQueue();
const incremental = time("incremental", () => daemon.updateTiddler($tw.wiki, changedTitle));

const commandRun = time("command", () => {
	const commander = { streams: { output: process.stdout, error: process.stderr } };
	const command = new commandModule.Command([], commander);
	return command.execute();
});
const summaryTiddler = $tw.wiki.getTiddler("$:/temp/static-index/summary");
const summary = summaryTiddler ? JSON.parse(summaryTiddler.fields.text) : null;

console.log("");
console.log("=== headless-graph-prerender demo ===");
console.log("tiddlers in wiki       : " + $tw.wiki.getTiddlers().length);
console.log("index nodes / edges     : " + stats.nodes + " / " + stats.edges);
console.log("terms in inverted index : " + stats.terms);
console.log("full rebuild            : " + rebuild.ms.toFixed(1) + " ms (budget 1500 ms)");
console.log("single incremental edit : " + incremental.ms.toFixed(1) + " ms (budget 15 ms)");
console.log("--prerender-graph       : " + commandRun.ms.toFixed(1) + " ms" +
	(summary ? " (" + summary.nodes + " nodes, " + summary.exportedFragments + " fragments)" : ""));
console.log("");
console.log("[hg-backlinks[0.5]] Synthetic 0001 -> " + JSON.stringify(backlinks));
console.log("[hg-related[5]]     Synthetic 0001 -> " + JSON.stringify(related));
console.log("[hg-path]           0001 -> 0005   -> " + JSON.stringify(pathResult));
console.log("[hg-orphans[]]      count=" + orphans.length + " -> " + JSON.stringify(orphans.slice(0, 8)));
console.log("");
if (summary) {
	console.log("summary tiddler: $:/temp/static-index/summary");
	console.log(JSON.stringify(summary, null, 2));
}
console.log("");

// Avoid waiting for TiddlyWiki's queued change events after the command wrote
// ~1,200 static fragments into the store.
daemon.cancelPending();
process.exit(0);
