document.addEventListener("DOMContentLoaded", async () => {
  const svg = document.getElementById("networkGraph");
  const wrap = document.getElementById("networkGraphWrap");
  const message = document.getElementById("networkMessage");
  const inspectorTitle = document.getElementById("inspectorTitle");
  const inspectorSubtitle = document.getElementById("inspectorSubtitle");
  const inspectorContent = document.getElementById("inspectorContent");
  const list = document.getElementById("networkCaseList");
  const displayLimit = 150;
  const graphDisplayLimit = 36;
  const svgNS = "http://www.w3.org/2000/svg";
  let graph;
  let selectedId = null;

  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const svgElement = (tag, attributes = {}) => {
    const node = document.createElementNS(svgNS, tag);
    Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, value));
    return node;
  };
  const caseUrl = candidateId => `/candidates/${encodeURIComponent(candidateId)}`;
  const riskClass = risk => ["critical", "high", "medium", "low"].includes((risk || "").toLowerCase())
    ? risk.toLowerCase() : "low";

  function setMessage(text, error = false) {
    message.textContent = text;
    message.classList.toggle("error", error);
    message.hidden = !text;
  }

  function strengthText(value) {
    if (value >= 80) return "Strong exact match";
    if (value >= 60) return "Moderate exact match";
    return "Weak shared-infrastructure signal";
  }

  function showCase(node) {
    selectedId = node.id;
    inspectorTitle.textContent = node.label;
    inspectorSubtitle.textContent = `${node.type} · ${node.risk} heuristic risk · ${node.status}`;
    inspectorContent.replaceChildren();

    const open = element("a", "btn secondary inspector-open", "Open case file →");
    open.href = caseUrl(node.candidate_id);
    inspectorContent.append(open);

    const score = element("div", "inspector-score");
    score.append(element("span", "", "Candidate triage score"));
    score.append(element("b", "", `${node.score}/100`));
    inspectorContent.append(score);

    const connectedLinks = graph.links.filter(link =>
      link.source === node.id || link.target === node.id);
    const connectionsTitle = element("h4", "inspector-section-title",
      `Shared evidence (${connectedLinks.length} connection${connectedLinks.length === 1 ? "" : "s"})`);
    inspectorContent.append(connectionsTitle);
    if (!connectedLinks.length) {
      inspectorContent.append(element("p", "muted", "No matching identifiers found in other cases yet."));
    }
    connectedLinks.forEach(link => {
      const otherId = link.source === node.id ? link.target : link.source;
      const other = graph.nodeById.get(otherId);
      if (!other) return;
      const card = element("article", "connection-card");
      const heading = element("div", "connection-heading");
      heading.append(element("b", "", other.label));
      heading.append(element("span", `risk ${riskClass(other.risk)}`, `${other.risk} · ${link.strength}`));
      card.append(heading);
      card.append(element("small", "muted", strengthText(link.strength) +
        " · heuristic match strength, not probability or attribution"));
      link.evidence.forEach(evidence => {
        const detail = element("div", "matched-indicator");
        detail.append(element("b", "", evidence.type.replaceAll("_", " ")));
        detail.append(element("code", "", evidence.value));
        detail.append(element("small", "muted",
          `Observed in ${evidence.source_fields.join(" and ")} · ${evidence.observed_at.join(" / ")}`));
        detail.append(element("small", "muted",
          `Timestamp basis: ${evidence.time_basis.join(" / ")}.`));
        detail.append(element("small", "muted",
          `Lowest observation source-quality value: ${evidence.source_quality}`));
        card.append(detail);
      });
      card.append(element("p", "verification-prompt",
        "Verify both sources and ownership independently. Shared public infrastructure may be coincidental."));
      const linkCase = element("a", "text-link", "Open connected case →");
      linkCase.href = caseUrl(other.candidate_id);
      card.append(linkCase);
      inspectorContent.append(card);
    });

    const observedTitle = element("h4", "inspector-section-title",
      `Observed identifiers (${node.observations.length})`);
    inspectorContent.append(observedTitle);
    if (!node.observations.length) {
      inspectorContent.append(element("p", "muted", "No supported identifiers extracted from this record."));
    }
    node.observations.forEach(observation => {
      const row = element("div", "observation-row");
      row.append(element("b", "", observation.kind.replaceAll("_", " ")));
      row.append(element("code", "", observation.value));
      row.append(element("small", "muted",
        `${observation.source_field} · ${observation.time_basis} ${observation.observed_at} · provenance weight ${observation.source_confidence}`));
      inspectorContent.append(row);
    });
    drawGraph();
  }

  function drawGraph() {
    const width = Math.max(320, Math.floor(wrap.clientWidth));
    const height = width < 600 ? 430 : 540;
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.replaceChildren();
    const nodes = graph.nodes.slice(0, graphDisplayLimit);
    const shownIds = new Set(nodes.map(node => node.id));
    const links = graph.links.filter(link => shownIds.has(link.source) && shownIds.has(link.target));
    const centerX = width / 2;
    const centerY = height / 2;
    const radiusX = Math.max(90, width * 0.39);
    const radiusY = Math.max(95, height * 0.37);
    const points = new Map();

    nodes.forEach((node, index) => {
      const angle = -Math.PI / 2 + (2 * Math.PI * index / Math.max(nodes.length, 1));
      points.set(node.id, {
        x: centerX + Math.cos(angle) * radiusX,
        y: centerY + Math.sin(angle) * radiusY,
      });
    });

    links.forEach(link => {
      const from = points.get(link.source);
      const to = points.get(link.target);
      if (!from || !to) return;
      const line = svgElement("line", {
        x1: from.x, y1: from.y, x2: to.x, y2: to.y,
        class: `network-edge${selectedId && link.source !== selectedId && link.target !== selectedId ? " dimmed" : ""}`,
      });
      const title = svgElement("title");
      title.textContent = `${link.label} · strength ${link.strength}/100 (not a probability)`;
      line.append(title);
      svg.append(line);
    });

    nodes.forEach(node => {
      const point = points.get(node.id);
      const group = svgElement("g", {
        class: `network-node risk-${riskClass(node.risk)}${selectedId === node.id ? " selected" : ""}`,
        tabindex: "0",
        role: "button",
        "aria-label": `${node.label}, ${node.type}, ${node.risk} risk, ${node.observations.length} identifiers`,
      });
      const title = svgElement("title");
      title.textContent = `${node.label} · ${node.type} · ${node.risk} · ${node.observations.length} identifiers`;
      group.append(title);
      group.append(svgElement("circle", {cx: point.x, cy: point.y, r: 18}));
      const text = svgElement("text", {x: point.x, y: point.y + 33, "text-anchor": "middle"});
      text.textContent = node.label.length > 19 ? `${node.label.slice(0, 18)}…` : node.label;
      group.append(text);
      group.addEventListener("click", () => showCase(node));
      group.addEventListener("keydown", event => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          showCase(node);
        }
      });
      svg.append(group);
    });
  }

  function renderCaseList() {
    const nodes = graph.nodes;
    document.getElementById("networkCaseListCount").textContent = `${nodes.length} CASES`;
    const visible = nodes.slice(0, displayLimit);
    visible.forEach(node => {
      const button = element("button", "network-case-row");
      button.type = "button";
      button.setAttribute("aria-label", `Inspect ${node.label}`);
      const risk = element("span", `risk ${riskClass(node.risk)}`, node.risk);
      const summary = element("span", "network-case-summary");
      summary.append(element("b", "", node.label));
      summary.append(element("small", "", `${node.type} · ${node.status} · ${node.observations.length} identifiers`));
      button.append(risk, summary, element("span", "network-case-arrow", "→"));
      button.addEventListener("click", () => showCase(node));
      list.append(button);
    });
    if (nodes.length > displayLimit) {
      list.append(element("p", "muted network-truncation",
        `Showing the first ${displayLimit} cases here. Narrow the workspace before investigating larger networks.`));
    }
  }

  try {
    const response = await fetch("/api/network", {headers: {"Accept": "application/json"}});
    if (!response.ok) throw new Error(`Network data request failed (${response.status}).`);
    graph = await response.json();
    graph.nodeById = new Map(graph.nodes.map(node => [node.id, node]));
    const linked = new Set(graph.links.flatMap(link => [link.source, link.target]));
    document.getElementById("networkNodeCount").textContent = graph.nodes.length;
    document.getElementById("networkLinkCount").textContent = graph.links.length;
    document.getElementById("networkLinkedCount").textContent = linked.size;
    document.getElementById("networkSuppressedCount").textContent = graph.suppressed_common_indicators;
    const capNotes = [];
    if (graph.suppressed_common_indicators) {
      capNotes.push(`${graph.suppressed_common_indicators} high-volume indicator(s) were not expanded.`);
    }
    if (graph.suppressed_link_pairs) {
      capNotes.push(`${graph.suppressed_link_pairs} additional evidence pair(s) were omitted by the safety limit.`);
    }
    document.getElementById("networkCapMessage").textContent =
      capNotes.length ? ` ${capNotes.join(" ")}` : "";
    if (!graph.nodes.length) {
      setMessage("No candidate cases yet. Add a case manually or import an authorized CSV to begin.", false);
    } else if (!graph.links.length) {
      setMessage("No exact shared identifiers found yet. Add source URLs, phone observations or app publisher details to explore relationships.", false);
    } else {
      setMessage("");
    }
    renderCaseList();
    drawGraph();
    if (graph.nodes.length) showCase(graph.nodes[0]);
    window.addEventListener("resize", drawGraph);
  } catch (error) {
    setMessage(error.message || "Could not load network data. Please retry.", true);
    inspectorContent.replaceChildren(element("p", "muted", "Refresh the page to retry loading the graph."));
  }
});
