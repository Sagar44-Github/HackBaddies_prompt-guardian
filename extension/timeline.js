(function () {
  const NS = "http://www.w3.org/2000/svg";
  const STYLE_ID = "pg-severity-timeline-style";

  function ensureGlobalStyles() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      @keyframes pgTimelinePulse {
        0% { transform: translate(-50%, -50%) scale(1); opacity: 0.95; }
        100% { transform: translate(-50%, -50%) scale(1.85); opacity: 0; }
      }
      .pg-timeline-tooltip {
        position: absolute;
        background: #1E293B;
        border-radius: 10px;
        padding: 12px;
        min-width: 260px;
        max-width: 320px;
        box-shadow: 0 8px 25px rgba(0,0,0,0.5);
        z-index: 9999;
        pointer-events: none;
        color: #E2E8F0;
        font-family: Inter, "Segoe UI", sans-serif;
        font-size: 12px;
        display: none;
      }
      .pg-timeline-tooltip .prompt-snippet {
        margin-top: 8px;
        background: #0F172A;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 8px;
        font-family: "JetBrains Mono", Consolas, monospace;
        font-size: 11px;
        color: #CBD5E1;
      }
      .pg-timeline-toolbar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
        gap: 10px;
      }
      .pg-timeline-btns {
        display: inline-flex;
        gap: 6px;
      }
      .pg-timeline-btn {
        background: #0F172A;
        color: #CBD5E1;
        border: 1px solid #334155;
        border-radius: 6px;
        font-size: 11px;
        line-height: 1;
        padding: 6px 10px;
        cursor: pointer;
      }
      .pg-timeline-btn:hover { background: #1E293B; }
      .pg-timeline-btn:disabled { opacity: 0.6; cursor: not-allowed; }
    `;
    document.head.appendChild(style);
  }

  window.renderSeverityTimeline = function renderSeverityTimeline(containerId, events, options) {
    const container = document.getElementById(containerId);
    if (!container) return;

    ensureGlobalStyles();

    const opts = Object.assign(
      {
        width: container.clientWidth || 700,
        height: 280,
        animationDelay: 80,
        enableZoom: true,
        enablePlayback: true,
        theme: "dark",
      },
      options || {}
    );

    const isMobile = (container.clientWidth || opts.width) < 500;
    const baseDotRadius = isMobile ? 5 : 7;
    const margin = {
      top: opts.height * 0.1,
      right: 20,
      bottom: opts.height * 0.16,
      left: isMobile ? 10 : 98,
    };

    const existingTooltip = document.getElementById(`pg-timeline-tooltip-${containerId}`);
    if (existingTooltip) existingTooltip.remove();
    container.innerHTML = "";

    const tooltip = document.createElement("div");
    tooltip.id = `pg-timeline-tooltip-${containerId}`;
    tooltip.className = "pg-timeline-tooltip";
    document.body.appendChild(tooltip);

    const toolbar = document.createElement("div");
    toolbar.className = "pg-timeline-toolbar";
    container.appendChild(toolbar);

    const leftButtons = document.createElement("div");
    leftButtons.className = "pg-timeline-btns";
    toolbar.appendChild(leftButtons);

    const rightButtons = document.createElement("div");
    rightButtons.className = "pg-timeline-btns";
    toolbar.appendChild(rightButtons);

    let replayBtn = null;
    if (opts.enablePlayback) {
      replayBtn = document.createElement("button");
      replayBtn.className = "pg-timeline-btn";
      replayBtn.textContent = "▶ Replay Session";
      leftButtons.appendChild(replayBtn);
    }

    let zoom = 1;
    if (opts.enableZoom) {
      const zoomIn = document.createElement("button");
      zoomIn.className = "pg-timeline-btn";
      zoomIn.textContent = "🔍+";
      const zoomOut = document.createElement("button");
      zoomOut.className = "pg-timeline-btn";
      zoomOut.textContent = "🔍−";
      const zoomReset = document.createElement("button");
      zoomReset.className = "pg-timeline-btn";
      zoomReset.textContent = "⊡";
      rightButtons.appendChild(zoomIn);
      rightButtons.appendChild(zoomOut);
      rightButtons.appendChild(zoomReset);
      zoomIn.addEventListener("click", () => { zoom = Math.min(8, zoom * 2); renderFrame(false); });
      zoomOut.addEventListener("click", () => { zoom = Math.max(1, zoom / 2); renderFrame(false); });
      zoomReset.addEventListener("click", () => { zoom = 1; scrollWrap.scrollLeft = 0; renderFrame(false); });
    }

    const scrollWrap = document.createElement("div");
    scrollWrap.style.overflowX = "auto";
    scrollWrap.style.overflowY = "hidden";
    scrollWrap.style.paddingBottom = "8px";
    container.appendChild(scrollWrap);
    scrollWrap.addEventListener("scroll", () => renderFrame(false));

    const legend = document.createElement("div");
    legend.style.display = "flex";
    legend.style.flexWrap = "wrap";
    legend.style.gap = "14px";
    legend.style.alignItems = "center";
    legend.style.marginTop = "8px";
    legend.style.fontSize = "11px";
    legend.style.color = "#94A3B8";
    container.appendChild(legend);

    function legendItem(color, text, extra) {
      const item = document.createElement("div");
      item.style.display = "inline-flex";
      item.style.alignItems = "center";
      item.style.gap = "6px";
      const dot = document.createElement("span");
      dot.style.display = "inline-block";
      dot.style.width = "9px";
      dot.style.height = "9px";
      dot.style.borderRadius = "50%";
      dot.style.background = color;
      dot.style.position = "relative";
      if (extra === "ring") dot.style.boxShadow = "0 0 0 2px #7C3AED";
      if (extra === "x") dot.textContent = "×";
      if (extra === "x") {
        dot.style.color = "#FFF";
        dot.style.textAlign = "center";
        dot.style.fontSize = "10px";
        dot.style.lineHeight = "9px";
      }
      const label = document.createElement("span");
      label.textContent = text;
      item.append(dot, label);
      legend.appendChild(item);
    }

    legendItem("#EF4444", "CRITICAL");
    legendItem("#F59E0B", "HIGH");
    legendItem("#3B82F6", "MEDIUM");
    legendItem("#10B981", "SAFE");
    legendItem("transparent", "Multilingual Attack", "ring");
    legendItem("#64748B", "User Override", "x");

    const sortedEvents = Array.isArray(events)
      ? [...events].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
      : [];

    const bands = [
      { name: "CRITICAL", yColor: "#EF4444", bg: "rgba(239,68,68,0.08)" },
      { name: "HIGH", yColor: "#F59E0B", bg: "rgba(245,158,11,0.08)" },
      { name: "MEDIUM", yColor: "#3B82F6", bg: "rgba(59,130,246,0.08)" },
      { name: "SAFE", yColor: "#10B981", bg: "rgba(16,185,129,0.08)" },
    ];

    let pinnedIndex = -1;
    let dotRefs = [];
    let axisMin = null;
    let axisMax = null;

    function createSvgEl(tag, attrs) {
      const el = document.createElementNS(NS, tag);
      Object.keys(attrs || {}).forEach((k) => el.setAttribute(k, attrs[k]));
      return el;
    }

    function getBand(riskScore) {
      if (riskScore >= 90) return 0;
      if (riskScore >= 70) return 1;
      if (riskScore >= 40) return 2;
      return 3;
    }

    function getColor(riskScore) {
      return ["#10B981", "#3B82F6", "#F59E0B", "#EF4444"][Math.floor(Math.min(99, riskScore) / 30)] || "#10B981";
    }

    function darken(hex) {
      const safeHex = hex.replace("#", "");
      const n = parseInt(safeHex, 16);
      const r = Math.max(0, ((n >> 16) & 255) - 32);
      const g = Math.max(0, ((n >> 8) & 255) - 32);
      const b = Math.max(0, (n & 255) - 32);
      return `rgb(${r},${g},${b})`;
    }

    function formatTickTime(date, useSeconds) {
      if (useSeconds) {
        return date.toLocaleTimeString([], { minute: "2-digit", second: "2-digit" });
      }
      return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }

    function formatTooltipDate(iso) {
      return new Date(iso).toLocaleString([], {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "2-digit",
        second: "2-digit",
      }).replace(",", " —");
    }

    function interpolateX(ts, idx, total, plotLeft, plotWidth) {
      if (!axisMin || !axisMax || axisMax - axisMin === 0) {
        const fraction = total <= 1 ? 0.5 : idx / (total - 1);
        return plotLeft + fraction * plotWidth;
      }
      const ratio = (ts - axisMin) / (axisMax - axisMin);
      return plotLeft + ratio * plotWidth;
    }

    function hideTooltip() {
      if (pinnedIndex === -1) tooltip.style.display = "none";
    }

    function showTooltip(eventObj, dotEl, color) {
      const lang = eventObj.detected_language;
      const isNonEnglish = lang && String(lang).toLowerCase() !== "english";
      tooltip.style.border = `1px solid ${color}`;
      tooltip.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
          <span style="display:inline-block;padding:2px 8px;border-radius:999px;background:${color}22;color:${color};font-weight:700;">
            ${(eventObj.risk_score || 0).toFixed(1)}%
          </span>
          <span style="color:#CBD5E1;font-weight:600;">${eventObj.attack_type || "Safe Prompt"}</span>
        </div>
        <div style="margin-top:8px;color:#94A3B8;">${formatTooltipDate(eventObj.timestamp)}</div>
        ${isNonEnglish ? `<div style="margin-top:8px;display:inline-block;background:#7C3AED22;color:#A78BFA;border:1px solid #7C3AED66;border-radius:999px;padding:2px 8px;font-size:10px;">${lang}</div>` : ""}
        <div class="prompt-snippet">${(eventObj.prompt || "").slice(0, 80)}</div>
        <div style="margin-top:9px;color:#94A3B8;">Action: <b style="color:#E2E8F0;">${eventObj.action || "ALLOW"}</b> | Decision: <b style="color:#E2E8F0;">${eventObj.user_action || "auto"}</b></div>
      `;
      tooltip.style.display = "block";
      const rect = dotEl.getBoundingClientRect();
      tooltip.style.left = `${window.scrollX + rect.left + 15}px`;
      tooltip.style.top = `${window.scrollY + rect.top - tooltip.offsetHeight - 15}px`;
    }

    function renderFrame(playAnimation) {
      const width = Math.max(opts.width, container.clientWidth || opts.width);
      const fullWidth = Math.round(width * zoom);
      const height = opts.height;
      const plotLeft = margin.left;
      const plotRight = fullWidth - margin.right;
      const plotWidth = Math.max(10, plotRight - plotLeft);
      const plotTop = margin.top;
      const plotBottom = height - margin.bottom;
      const plotHeight = Math.max(10, plotBottom - plotTop);
      const bandHeight = plotHeight / 4;

      scrollWrap.innerHTML = "";
      const svg = createSvgEl("svg", { width: fullWidth, height, viewBox: `0 0 ${fullWidth} ${height}` });
      scrollWrap.appendChild(svg);

      if (!sortedEvents.length) {
        const txt = createSvgEl("text", {
          x: fullWidth / 2,
          y: height / 2,
          "text-anchor": "middle",
          fill: "#64748B",
          "font-size": "12",
        });
        txt.textContent = "No session data available. Use Prompt Guardian on ChatGPT to generate timeline data.";
        svg.appendChild(txt);
        return;
      }

      axisMin = new Date(sortedEvents[0].timestamp).getTime();
      axisMax = new Date(sortedEvents[sortedEvents.length - 1].timestamp).getTime();

      for (let i = 0; i < 4; i += 1) {
        const y = plotTop + i * bandHeight;
        svg.appendChild(createSvgEl("rect", { x: 0, y, width: fullWidth, height: bandHeight, fill: bands[i].bg }));
        if (!isMobile) {
          const label = createSvgEl("text", {
            x: 12,
            y: y + bandHeight / 2 + 4,
            fill: bands[i].yColor,
            "font-size": "11",
            "font-weight": "700",
          });
          label.textContent = bands[i].name;
          svg.appendChild(label);
        }
      }

      const visibleStart = axisMin + ((axisMax - axisMin) * (scrollWrap.scrollLeft / Math.max(1, fullWidth - width)));
      const visibleEnd = visibleStart + (axisMax - axisMin) / zoom;
      const visibleDuration = Math.max(1, visibleEnd - visibleStart);
      let tickStep = 60 * 1000;
      if (visibleDuration >= 5 * 60 * 1000 && visibleDuration < 60 * 60 * 1000) tickStep = 5 * 60 * 1000;
      if (visibleDuration >= 60 * 60 * 1000 && visibleDuration < 24 * 60 * 60 * 1000) tickStep = 60 * 60 * 1000;

      const tickStart = Math.floor(axisMin / tickStep) * tickStep;
      const useSeconds = (axisMax - axisMin) < 5 * 60 * 1000;
      for (let t = tickStart; t <= axisMax + tickStep; t += tickStep) {
        const x = interpolateX(t, 0, 0, plotLeft, plotWidth);
        if (x < plotLeft || x > plotRight) continue;
        svg.appendChild(createSvgEl("line", {
          x1: x, x2: x, y1: plotTop, y2: plotBottom, stroke: "rgba(255,255,255,0.05)", "stroke-width": "1"
        }));
        svg.appendChild(createSvgEl("line", {
          x1: x, x2: x, y1: plotBottom, y2: plotBottom + 5, stroke: "#64748B", "stroke-width": "1"
        }));
        const label = createSvgEl("text", { x, y: plotBottom + 16, "text-anchor": "middle", fill: "#64748B", "font-size": "10" });
        label.textContent = formatTickTime(new Date(t), useSeconds);
        svg.appendChild(label);
      }

      svg.appendChild(createSvgEl("line", { x1: plotLeft, x2: plotRight, y1: plotBottom, y2: plotBottom, stroke: "#334155", "stroke-width": "1.5" }));

      dotRefs = [];
      sortedEvents.forEach((eventObj, index) => {
        const eventTime = new Date(eventObj.timestamp).getTime();
        const bandIdx = getBand(eventObj.risk_score || 0);
        const color = [ "#EF4444", "#F59E0B", "#3B82F6", "#10B981" ][bandIdx];
        const y = plotTop + bandIdx * bandHeight + bandHeight / 2;
        const x = interpolateX(eventTime, index, sortedEvents.length, plotLeft, plotWidth);

        const g = createSvgEl("g", {});
        g.style.transformOrigin = `${x}px ${y}px`;
        g.style.transition = "opacity 0.3s, transform 0.3s";
        g.style.opacity = playAnimation ? "0" : "1";
        g.style.transform = playAnimation ? "scale(0)" : "scale(1)";

        if (eventObj.is_multilingual_attack === true) {
          g.appendChild(createSvgEl("circle", { cx: x, cy: y, r: baseDotRadius + 4, fill: "none", stroke: "#7C3AED", "stroke-width": "2" }));
        }

        if (pinnedIndex === index) {
          const pulse = createSvgEl("circle", { cx: x, cy: y, r: baseDotRadius + 2, fill: "none", stroke: "rgba(255,255,255,0.85)", "stroke-width": "2" });
          pulse.style.transformOrigin = `${x}px ${y}px`;
          pulse.style.animation = "pgTimelinePulse 1.2s ease-out infinite";
          g.appendChild(pulse);
        }

        const dotRadius = pinnedIndex === index ? baseDotRadius + 5 : baseDotRadius;
        const dot = createSvgEl("circle", {
          cx: x, cy: y, r: dotRadius, fill: color, stroke: darken(color), "stroke-width": "2", cursor: "pointer"
        });
        g.appendChild(dot);

        if (String(eventObj.user_action || "").toLowerCase() === "overridden") {
          g.appendChild(createSvgEl("line", { x1: x - 3, y1: y - 3, x2: x + 3, y2: y + 3, stroke: "#FFFFFF", "stroke-width": "1.5" }));
          g.appendChild(createSvgEl("line", { x1: x + 3, y1: y - 3, x2: x - 3, y2: y + 3, stroke: "#FFFFFF", "stroke-width": "1.5" }));
        }

        dot.addEventListener("mouseenter", () => {
          dot.setAttribute("r", String(baseDotRadius + 3));
          dot.setAttribute("stroke", "#FFFFFF");
          showTooltip(eventObj, dot, color);
        });
        dot.addEventListener("mouseleave", () => {
          if (pinnedIndex !== index) {
            dot.setAttribute("r", String(baseDotRadius));
            dot.setAttribute("stroke", darken(color));
            hideTooltip();
          }
        });
        dot.addEventListener("click", (e) => {
          e.stopPropagation();
          pinnedIndex = index;
          renderFrame(false);
          const newDot = dotRefs[index];
          if (newDot) showTooltip(eventObj, newDot, color);
        });

        dotRefs[index] = dot;
        svg.appendChild(g);

        if (playAnimation) {
          setTimeout(() => {
            g.style.opacity = "1";
            g.style.transform = "scale(1.2)";
            setTimeout(() => { g.style.transform = "scale(1)"; }, 130);
          }, index * opts.animationDelay);
        }
      });

      svg.addEventListener("click", () => {
        if (pinnedIndex !== -1) {
          pinnedIndex = -1;
          tooltip.style.display = "none";
          renderFrame(false);
        }
      });
    }

    function runPlayback() {
      if (!replayBtn) return;
      replayBtn.disabled = true;
      replayBtn.textContent = "⏸ Playing...";
      pinnedIndex = -1;
      tooltip.style.display = "none";
      renderFrame(true);
      const ms = (sortedEvents.length * opts.animationDelay) + 450;
      setTimeout(() => {
        replayBtn.disabled = false;
        replayBtn.textContent = "▶ Replay Session";
      }, ms);
    }

    if (replayBtn) replayBtn.addEventListener("click", runPlayback);
    renderFrame(true);
  };
})();
