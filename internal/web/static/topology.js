/*
 * The topology island.
 *
 * Every other view in this GUI is drawn by the server. A network graph is the
 * one place where that is not enough: an analyst has to drag a node out of a
 * hairball, zoom into a cell of the plant and follow an edge, and none of
 * that survives a page reload. So Cytoscape draws the graph here, from the
 * same JSON the server would render as a picture.
 *
 * Three rules this file keeps:
 *
 *   - It is an external script with no inline code, so the strict content
 *     security policy needs no exception for it.
 *   - It never replaces the server-drawn picture until it has drawn
 *     something, so a browser with no scripting, or one where this file fails
 *     to load, still shows the network.
 *   - Colours come from the stylesheet's own custom properties, so the graph
 *     follows the theme, the accent and the contrast settings instead of
 *     carrying a second palette that drifts from the first.
 */
(function () {
	"use strict";

	var container = document.getElementById("topo-graph");
	if (!container || typeof cytoscape !== "function") {
		// No graph on this page, or the vendored library did not load. The
		// server's picture is already on the page; leave it alone.
		return;
	}

	var staticFigure = document.getElementById("topo-static");
	var fitButton = document.getElementById("topo-fit");
	var pngLink = document.getElementById("topo-png");

	var ROW_HEIGHT = 170;
	var COLUMN_WIDTH = 150;
	var BLOCK_GAP = 90;
	/* A crowded level wraps over several lines inside its own band. Without
	   it a plant with thirty controllers on one level is drawn as one band
	   wider than any screen, and fitting that into the viewport shrinks every
	   node to a dot. */
	var MAX_PER_ROW = 12;
	var SUB_ROW_STEP = 70;

	function token(name, fallback) {
		var value = getComputedStyle(document.documentElement).getPropertyValue(name);
		value = (value || "").trim();
		return value === "" ? fallback : value;
	}

	function palette() {
		return {
			read: token("--c-read", "#5b8def"),
			write: token("--c-write", "#e8a33d"),
			control: token("--c-control", "#d9544f"),
			program: token("--c-program", "#9b51e0"),
			firmware: token("--c-firmware", "#c2185b"),
			diagnostic: token("--c-diagnostic", "#45b6ac"),
			discovery: token("--c-discovery", "#8d99ae"),
			other: token("--c-other", "#b8bfc9"),
			accent: token("--accent", "#5b8def"),
			muted: token("--muted", "#5b636e"),
			text: token("--text", "#1b1f24"),
			panel: token("--panel", "#ffffff"),
			border: token("--border", "#d7dce3")
		};
	}

	function levelLabels() {
		try {
			return JSON.parse(container.dataset.levels || "{}");
		} catch (err) {
			return {};
		}
	}

	function levelKey(level) {
		return level === undefined || level === null || level < 0 ? "unknown" : String(level);
	}

	/* Positions for the layered layout: one row per Purdue level, in order,
	   with the unplaced devices in the last row. */
	function purduePositions(graph) {
		var rows = {};
		graph.nodes.forEach(function (node) {
			var key = levelKey(node.level);
			rows[key] = rows[key] || [];
			rows[key].push(node);
		});

		var order = ["0", "1", "2", "3", "4"].filter(function (key) {
			return rows[key];
		});
		Object.keys(rows).forEach(function (key) {
			if (order.indexOf(key) === -1 && key !== "unknown") {
				order.push(key);
			}
		});
		if (rows.unknown) {
			order.push("unknown");
		}

		var positions = {};
		var widest = 1;
		order.forEach(function (key) {
			widest = Math.max(widest, Math.min(rows[key].length, MAX_PER_ROW));
		});

		var y = 0;
		order.forEach(function (key) {
			var nodes = rows[key].slice().sort(function (a, b) {
				if (a.subnet !== b.subnet) {
					return (a.subnet || "").localeCompare(b.subnet || "");
				}
				return a.label.localeCompare(b.label);
			});
			var subRows = Math.ceil(nodes.length / MAX_PER_ROW);
			var perRow = Math.ceil(nodes.length / subRows);
			nodes.forEach(function (node, i) {
				positions[node.id] = {
					x: (((i % perRow) + 1) * widest * COLUMN_WIDTH) / (perRow + 1),
					y: y + Math.floor(i / perRow) * SUB_ROW_STEP
				};
			});
			y += Math.max(ROW_HEIGHT, subRows * SUB_ROW_STEP + 60);
		});
		return { positions: positions, groups: order, rows: rows };
	}

	/* Positions for the subnet layout: each subnet is a block of its own,
	   laid out in reading order. Deterministic, so the same project draws the
	   same picture twice. */
	function subnetPositions(graph) {
		var groups = {};
		graph.nodes.forEach(function (node) {
			var key = node.subnet || "";
			groups[key] = groups[key] || [];
			groups[key].push(node);
		});

		var names = Object.keys(groups).sort();
		var positions = {};
		var offsetX = 0;
		var offsetY = 0;
		var rowHeight = 0;
		names.forEach(function (name) {
			var nodes = groups[name].slice().sort(function (a, b) {
				return a.label.localeCompare(b.label);
			});
			var columns = Math.ceil(Math.sqrt(nodes.length));
			nodes.forEach(function (node, i) {
				positions[node.id] = {
					x: offsetX + (i % columns) * COLUMN_WIDTH,
					y: offsetY + Math.floor(i / columns) * (ROW_HEIGHT / 2)
				};
			});
			var width = columns * COLUMN_WIDTH + BLOCK_GAP;
			var height = Math.ceil(nodes.length / columns) * (ROW_HEIGHT / 2) + BLOCK_GAP;
			rowHeight = Math.max(rowHeight, height);
			offsetX += width;
			if (offsetX > 6 * COLUMN_WIDTH * 3) {
				offsetX = 0;
				offsetY += rowHeight;
				rowHeight = 0;
			}
		});
		return { positions: positions, groups: names, rows: groups };
	}

	function elements(graph, layout, labels) {
		var out = [];
		var parents = {};

		if (layout === "purdue") {
			graph.nodes.forEach(function (node) {
				var key = levelKey(node.level);
				if (!parents[key]) {
					parents[key] = true;
					out.push({
						data: {
							id: "group:" + key,
							label: labels[key] || key,
							kind: "group-box"
						},
						classes: "group-box",
						selectable: false,
						grabbable: false
					});
				}
			});
		} else if (layout === "subnet") {
			graph.nodes.forEach(function (node) {
				var key = node.subnet || "";
				if (key !== "" && !parents[key]) {
					parents[key] = true;
					out.push({
						data: { id: "group:" + key, label: key, kind: "group-box" },
						classes: "group-box",
						selectable: false,
						grabbable: false
					});
				}
			});
		}

		graph.nodes.forEach(function (node) {
			var parent;
			if (layout === "purdue") {
				parent = "group:" + levelKey(node.level);
			} else if (layout === "subnet" && node.subnet) {
				parent = "group:" + node.subnet;
			}
			out.push({
				data: {
					id: node.id,
					label: node.label,
					kind: node.kind,
					level: levelKey(node.level),
					role: node.role || "",
					vendor: node.vendor || "",
					subnet: node.subnet || "",
					protocols: (node.protocols || []).join(", "),
					levelNote: node.level_note || "",
					href: node.href || "",
					events: node.events || 0,
					weight: Math.log10((node.events || 0) + 10),
					context: node.context ? "yes" : "no",
					parent: parent
				},
				classes: node.context ? "context" : ""
			});
		});

		graph.edges.forEach(function (edge) {
			out.push({
				data: {
					id: edge.id,
					source: edge.src,
					target: edge.dst,
					protocol: edge.protocol,
					klass: edge.class || "other",
					events: edge.events || 0,
					width: Math.min(6, 1 + Math.log10((edge.events || 0) + 1)),
					href: edge.href || "",
					directed: edge.directed ? "yes" : "no"
				},
				classes: edge.directed ? "" : "undirected"
			});
		});
		return out;
	}

	function style(colors) {
		return [
			{
				selector: "node",
				style: {
					"background-color": colors.accent,
					"border-color": colors.panel,
					"border-width": 2,
					label: "data(label)",
					color: colors.text,
					"font-size": 11,
					"text-valign": "bottom",
					"text-margin-y": 4,
					"text-background-color": colors.panel,
					"text-background-opacity": 0.75,
					"text-background-padding": 2,
					width: "mapData(weight, 1, 5, 18, 54)",
					height: "mapData(weight, 1, 5, 18, 54)"
				}
			},
			{ selector: 'node[kind = "gateway"]', style: { "background-color": colors.discovery, shape: "diamond" } },
			{ selector: 'node[kind = "group"]', style: { "background-color": colors.diagnostic, shape: "hexagon" } },
			{ selector: 'node[kind = "unknown"]', style: { "background-color": colors.other, shape: "ellipse" } },
			{ selector: 'node[role = "plc_rtu_ied"]', style: { shape: "round-rectangle" } },
			{ selector: 'node[role = "engineering_workstation"]', style: { shape: "triangle" } },
			{
				selector: "node.context",
				style: { opacity: 0.35, "text-opacity": 0.5 }
			},
			{
				selector: "node.group-box",
				style: {
					"background-opacity": 0.06,
					"background-color": colors.muted,
					"border-color": colors.border,
					"border-width": 1,
					shape: "round-rectangle",
					label: "data(label)",
					"text-valign": "top",
					"text-halign": "center",
					"text-margin-y": -6,
					color: colors.muted,
					"font-size": 12,
					padding: 24
				}
			},
			{
				selector: "edge",
				style: {
					"line-color": colors.other,
					"curve-style": "bezier",
					width: "data(width)",
					opacity: 0.85,
					"target-arrow-color": colors.other,
					"target-arrow-shape": "triangle",
					"arrow-scale": 0.8
				}
			},
			{ selector: 'edge[klass = "read"]', style: { "line-color": colors.read, "target-arrow-color": colors.read } },
			{ selector: 'edge[klass = "write"]', style: { "line-color": colors.write, "target-arrow-color": colors.write } },
			{ selector: 'edge[klass = "control"]', style: { "line-color": colors.control, "target-arrow-color": colors.control } },
			{ selector: 'edge[klass = "program"]', style: { "line-color": colors.program, "target-arrow-color": colors.program } },
			{ selector: 'edge[klass = "firmware"]', style: { "line-color": colors.firmware, "target-arrow-color": colors.firmware } },
			{ selector: 'edge[klass = "diagnostic"]', style: { "line-color": colors.diagnostic, "target-arrow-color": colors.diagnostic } },
			{ selector: 'edge[klass = "discovery"]', style: { "line-color": colors.discovery, "target-arrow-color": colors.discovery } },
			{ selector: "edge.undirected", style: { "line-style": "dashed", "target-arrow-shape": "none" } },
			{ selector: ".faded", style: { opacity: 0.15, "text-opacity": 0.15 } },
			{ selector: ".highlight", style: { "border-color": colors.accent, "border-width": 4 } }
		];
	}

	function tooltip() {
		var box = document.createElement("div");
		box.className = "topo-tip";
		box.hidden = true;
		container.appendChild(box);
		return box;
	}

	function describe(node) {
		var parts = [node.data("label")];
		["vendor", "role", "subnet", "protocols", "levelNote"].forEach(function (field) {
			var value = node.data(field);
			if (value) {
				parts.push(value);
			}
		});
		parts.push(node.data("events") + " events");
		return parts;
	}

	function draw(graph) {
		// The container is hidden until there is something to draw in it, and
		// Cytoscape needs it visible to measure itself, so this comes first.
		container.hidden = false;

		var layout = container.dataset.layout || "purdue";
		var labels = levelLabels();
		var colors = palette();
		var placed = layout === "subnet" ? subnetPositions(graph) : purduePositions(graph);

		var cy = cytoscape({
			container: container,
			elements: elements(graph, layout, labels),
			style: style(colors),
			wheelSensitivity: 0.2,
			layout:
				layout === "force"
					? { name: "cose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 120, randomize: false }
					: {
							name: "preset",
							positions: function (node) {
								return placed.positions[node.id()] || { x: 0, y: 0 };
							},
							fit: true,
							padding: 40
						}
		});

		var tip = tooltip();
		cy.on("mouseover", "node[kind]", function (event) {
			var node = event.target;
			if (node.hasClass("group-box")) {
				return;
			}
			tip.textContent = describe(node).join(" · ");
			tip.hidden = false;
			node.addClass("highlight");
		});
		cy.on("mouseout", "node", function (event) {
			tip.hidden = true;
			event.target.removeClass("highlight");
		});
		cy.on("mousemove", function (event) {
			if (tip.hidden) {
				return;
			}
			var position = event.renderedPosition || { x: 0, y: 0 };
			tip.style.left = Math.round(position.x + 14) + "px";
			tip.style.top = Math.round(position.y + 14) + "px";
		});

		cy.on("tap", "node", function (event) {
			var href = event.target.data("href");
			if (href) {
				window.location.href = href;
			}
		});
		cy.on("tap", "edge", function (event) {
			var href = event.target.data("href");
			if (href) {
				window.location.href = href;
			}
		});

		if (fitButton) {
			fitButton.hidden = false;
			fitButton.addEventListener("click", function () {
				cy.fit(undefined, 40);
			});
		}
		if (pngLink) {
			pngLink.hidden = false;
			pngLink.addEventListener("click", function (event) {
				event.preventDefault();
				var data = cy.png({ full: true, scale: 2, bg: colors.panel });
				var temporary = document.createElement("a");
				temporary.href = data;
				temporary.download = "topology.png";
				document.body.appendChild(temporary);
				temporary.click();
				temporary.remove();
			});
		}

		// Only now is there something to look at, so the server's picture can
		// step aside.
		if (staticFigure) {
			staticFigure.hidden = true;
		}
		container.classList.add("ready");
	}

	var source = container.dataset.graph;
	if (!source) {
		return;
	}
	fetch(source, { credentials: "same-origin", headers: { Accept: "application/json" } })
		.then(function (response) {
			if (!response.ok) {
				throw new Error("topology: " + response.status);
			}
			return response.json();
		})
		.then(function (graph) {
			if (!graph || !graph.nodes || graph.nodes.length === 0) {
				return;
			}
			draw(graph);
		})
		.catch(function (err) {
			// The static picture is still on the page, which is the useful
			// half of this view; say why the other half is missing.
			console.error("otinv: drawing the topology failed", err);
		});
})();
