/**
 * radar.js — Prompt Guardian SVG Radar (Spider) Chart Engine
 *
 * A dependency-free, reusable SVG radar chart component for visualizing
 * multi-axis confidence scores. Supports inline (compact) and expanded modes
 * with animations, hover interactions, and dynamic axis configuration.
 *
 * Usage:
 *   window.renderRadarChart(containerId, axes, options)
 *
 *   axes = [{ label: 'Pattern', value: 90, color: '#F59E0B' }, ...]
 *   options = { size, mode, fillColor, animationDuration, ... }
 */

(function () {
  'use strict';

  // ── HELPER: POLAR TO CARTESIAN COORDINATE CONVERSION ─────────────────────
  /**
   * Convert polar coordinates (angle, radius) to Cartesian (x, y).
   *
   * Math explanation:
   *   - angle is in radians, where 0 = 3 o'clock (standard math convention)
   *   - We subtract PI/2 to rotate so 0 = 12 o'clock (top of chart)
   *   - x = center_x + radius * cos(angle)
   *   - y = center_y + radius * sin(angle)
   *   - SVG y-axis grows downward, so this formula is correct as-is
   *
   * @param {number} cx - center x coordinate
   * @param {number} cy - center y coordinate
   * @param {number} radius - distance from center
   * @param {number} angle - angle in radians (0 = top after offset)
   * @returns {Object} {x, y} cartesian coordinates
   */
  function polarToCartesian(cx, cy, radius, angle) {
    // Offset by -PI/2 to start from top (12 o'clock) instead of right (3 o'clock)
    const adjustedAngle = angle - (Math.PI / 2);
    return {
      x: cx + radius * Math.cos(adjustedAngle),
      y: cy + radius * Math.sin(adjustedAngle)
    };
  }

  // ── HELPER: LINEAR INTERPOLATION ───────────────────────────────────────────
  /**
   * Linearly interpolate between two values.
   * @param {number} start - starting value
   * @param {number} end - ending value
   * @param {number} t - progress (0.0 to 1.0)
   * @returns {number} interpolated value
   */
  function lerp(start, end, t) {
    return start + (end - start) * t;
  }

  // ── HELPER: CREATE SVG ELEMENT ───────────────────────────────────────────────
  /**
   * Create an SVG element with the given tag and attributes.
   * @param {string} tag - SVG element tag name (e.g., 'circle', 'path')
   * @param {Object} attrs - key-value pairs of SVG attributes
   * @returns {SVGElement} the created SVG element
   */
  function createSvgElement(tag, attrs) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      el.setAttribute(key, value);
    }
    return el;
  }

  // ── MAIN RENDER FUNCTION ─────────────────────────────────────────────────────
  /**
   * Render a radar (spider) chart into the specified container.
   *
   * @param {string} containerId - ID of the DOM element to render into
   * @param {Array} axes - Array of axis objects: { label, value, color }
   * @param {Object} options - Configuration options
   */
  window.renderRadarChart = function renderRadarChart(containerId, axes, options = {}) {
    const container = document.getElementById(containerId);
    if (!container) {
      console.warn(`[radar.js] Container #${containerId} not found`);
      return;
    }

    // ── CLEANUP PREVIOUS RENDER ───────────────────────────────────────────────
    // Remove any existing SVG and tooltip from previous render
    const existingSvg = container.querySelector('svg');
    if (existingSvg) existingSvg.remove();
    const existingTooltip = document.getElementById(`pg-radar-tooltip-${containerId}`);
    if (existingTooltip) existingTooltip.remove();

    // ── OPTIONS WITH DEFAULTS ───────────────────────────────────────────────────
    const opts = {
      size: options.size || 200,
      mode: options.mode || 'expanded', // 'inline' or 'expanded'
      fillColor: options.fillColor || '#EF4444',
      fillOpacity: options.fillOpacity !== undefined ? options.fillOpacity : 0.25,
      strokeColor: options.strokeColor || '#EF4444',
      strokeWidth: options.strokeWidth !== undefined ? options.strokeWidth : 2,
      animationDuration: options.animationDuration || 600,
      showValues: options.showValues !== undefined ? options.showValues : options.mode === 'expanded',
      gridLevels: options.gridLevels || 4,
      backgroundColor: options.backgroundColor || 'transparent'
    };

    const isInline = opts.mode === 'inline';
    const isExpanded = opts.mode === 'expanded';

    // ── VALIDATE AXES ───────────────────────────────────────────────────────────
    // Ensure minimum 3 axes for a proper polygon
    const validAxes = axes && axes.length >= 3 ? axes : [];
    const numAxes = Math.max(3, validAxes.length);

    // If no valid axes, show empty state
    if (validAxes.length === 0) {
      container.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:center;
                    height:${opts.size}px;color:#64748B;font-size:12px;">
          No data
        </div>`;
      return;
    }

    // ── GEOMETRY SETUP ─────────────────────────────────────────────────────────
    const cx = opts.size / 2;
    const cy = opts.size / 2;
    // Radius: leave padding for labels in expanded mode
    const radius = isInline ? opts.size * 0.42 : opts.size * 0.38;
    const padding = isInline ? 0 : 30; // extra space for labels

    // ── CREATE SVG ─────────────────────────────────────────────────────────────
    const svg = createSvgElement('svg', {
      width: opts.size,
      height: opts.size,
      viewBox: `0 0 ${opts.size} ${opts.size}`,
      style: `background:${opts.backgroundColor};`
    });
    container.appendChild(svg);

    // ── CREATE TOOLTIP (expanded mode only) ───────────────────────────────────────
    let tooltip = null;
    if (isExpanded) {
      tooltip = document.createElement('div');
      tooltip.id = `pg-radar-tooltip-${containerId}`;
      tooltip.style.cssText = `
        position: fixed;
        background: #1E293B;
        border: 1px solid ${opts.strokeColor};
        border-radius: 6px;
        padding: 6px 10px;
        font-size: 11px;
        color: #E2E8F0;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        pointer-events: none;
        z-index: 99999;
        display: none;
        font-family: Inter, 'Segoe UI', sans-serif;
      `;
      document.body.appendChild(tooltip);
    }

    // ── DRAW CONCENTRIC GRID RINGS ───────────────────────────────────────────────
    // Each ring represents a percentage level (25%, 50%, 75%, 100%)
    for (let level = 1; level <= opts.gridLevels; level++) {
      const levelPercent = level / opts.gridLevels; // 0.25, 0.5, 0.75, 1.0
      const levelRadius = radius * levelPercent;

      // Calculate vertices for this ring (regular polygon)
      const ringPoints = [];
      for (let i = 0; i < numAxes; i++) {
        const angle = (2 * Math.PI * i) / numAxes;
        const pos = polarToCartesian(cx, cy, levelRadius, angle);
        ringPoints.push(`${pos.x},${pos.y}`);
      }

      // Draw the ring polygon
      const ringColor = level === opts.gridLevels 
        ? 'rgba(255, 255, 255, 0.15)'  // outermost ring brighter
        : 'rgba(255, 255, 255, 0.08)';  // inner rings dimmer

      const ring = createSvgElement('polygon', {
        points: ringPoints.join(' '),
        fill: 'none',
        stroke: ringColor,
        'stroke-width': '1'
      });
      svg.appendChild(ring);

      // Add percentage labels on the first axis (top) in expanded mode
      if (isExpanded && i === 0) {
        const labelPos = polarToCartesian(cx, cy, levelRadius + 10, 0);
        const label = createSvgElement('text', {
          x: labelPos.x,
          y: labelPos.y + 3,
          fill: '#64748B',
          'font-size': '9',
          'text-anchor': 'middle',
          'font-family': 'Inter, sans-serif'
        });
        label.textContent = Math.round(levelPercent * 100);
        svg.appendChild(label);
      }
    }

    // ── DRAW AXIS LINES ─────────────────────────────────────────────────────────
    for (let i = 0; i < numAxes; i++) {
      const angle = (2 * Math.PI * i) / numAxes;
      const endPos = polarToCartesian(cx, cy, radius, angle);

      const axisLine = createSvgElement('line', {
        x1: cx,
        y1: cy,
        x2: endPos.x,
        y2: endPos.y,
        stroke: 'rgba(255, 255, 255, 0.1)',
        'stroke-width': '1'
      });
      svg.appendChild(axisLine);
    }

    // ── DRAW AXIS LABELS (expanded mode only) ───────────────────────────────────
    if (isExpanded) {
      for (let i = 0; i < validAxes.length; i++) {
        const axis = validAxes[i];
        const angle = (2 * Math.PI * i) / numAxes;
        const labelRadius = radius + padding;
        const labelPos = polarToCartesian(cx, cy, labelRadius, angle);

        const label = createSvgElement('text', {
          x: labelPos.x,
          y: labelPos.y,
          fill: axis.color || '#E2E8F0',
          'font-size': '11',
          'font-family': 'Inter, sans-serif',
          'font-weight': '500'
        });

        // Adjust text anchor based on position
        if (Math.abs(labelPos.x - cx) < 5) {
          // Top or bottom - center align
          label.setAttribute('text-anchor', 'middle');
          label.setAttribute('dy', labelPos.y < cy ? '-5' : '15');
        } else if (labelPos.x > cx) {
          // Right side - start align
          label.setAttribute('text-anchor', 'start');
          label.setAttribute('dx', '5');
        } else {
          // Left side - end align
          label.setAttribute('text-anchor', 'end');
          label.setAttribute('dx', '-5');
        }

        label.textContent = axis.label || '';
        svg.appendChild(label);
      }
    }

    // ── CALCULATE DATA POLYGON VERTICES ─────────────────────────────────────────
    // For animation, we'll interpolate from center (0,0) to final positions
    const finalVertices = [];
    for (let i = 0; i < numAxes; i++) {
      const axis = validAxes[i] || { value: 0 };
      const value = Math.min(100, Math.max(0, axis.value || 0)) / 100; // normalize to 0-1
      const angle = (2 * Math.PI * i) / numAxes;
      const finalPos = polarToCartesian(cx, cy, radius * value, angle);
      finalVertices.push(finalPos);
    }

    // ── CREATE DATA POLYGON ─────────────────────────────────────────────────────
    const dataPolygon = createSvgElement('polygon', {
      points: `${cx},${cy} ${cx},${cy} ${cx},${cy}`, // start collapsed at center
      fill: opts.fillColor,
      'fill-opacity': '0', // start transparent
      stroke: opts.strokeColor,
      'stroke-width': opts.strokeWidth,
      style: 'filter: drop-shadow(0 2px 4px rgba(0,0,0,0.3));'
    });
    svg.appendChild(dataPolygon);

    // ── CREATE VERTEX DOTS ─────────────────────────────────────────────────────
    const vertexDots = [];
    const dotRadius = isInline ? 3 : 4;

    for (let i = 0; i < numAxes; i++) {
      const dot = createSvgElement('circle', {
        cx: cx,
        cy: cy, // start at center
        r: dotRadius,
        fill: opts.strokeColor,
        style: 'cursor: pointer; transition: r 0.2s;'
      });
      svg.appendChild(dot);
      vertexDots.push(dot);

      // Add hover interaction in expanded mode
      if (isExpanded && validAxes[i]) {
        const axis = validAxes[i];

        dot.addEventListener('mouseenter', (e) => {
          dot.setAttribute('r', '6');
          if (tooltip) {
            tooltip.innerHTML = `
              <div style="font-weight:700;color:${axis.color || '#E2E8F0'};">
                ${axis.label || 'Axis'}
              </div>
              <div style="color:#94A3B8;">${axis.value || 0}%</div>
            `;
            tooltip.style.display = 'block';
            // Position tooltip near the dot
            const rect = dot.getBoundingClientRect();
            tooltip.style.left = (rect.left + window.scrollX + 10) + 'px';
            tooltip.style.top = (rect.top + window.scrollY - 40) + 'px';
          }
        });

        dot.addEventListener('mouseleave', () => {
          dot.setAttribute('r', String(dotRadius));
          if (tooltip) tooltip.style.display = 'none';
        });
      }
    }

    // ── CREATE VALUE LABELS (expanded mode only) ─────────────────────────────────
    const valueLabels = [];
    if (isExpanded && opts.showValues) {
      for (let i = 0; i < numAxes; i++) {
        const axis = validAxes[i];
        if (!axis) continue;

        const label = createSvgElement('text', {
          x: cx,
          y: cy,
          fill: '#FFFFFF',
          'font-size': '10',
          'font-weight': 'bold',
          'font-family': 'Inter, sans-serif',
          'text-anchor': 'middle',
          style: 'opacity: 0;'
        });
        label.textContent = `${axis.value || 0}%`;
        svg.appendChild(label);
        valueLabels.push(label);
      }
    }

    // ── CREATE CENTER AVERAGE LABEL ─────────────────────────────────────────────
    let centerLabel = null;
    let centerSublabel = null;

    if (validAxes.length > 0) {
      const avgValue = validAxes.reduce((sum, a) => sum + (a.value || 0), 0) / validAxes.length;

      if (isInline) {
        // Inline: just the number
        centerLabel = createSvgElement('text', {
          x: cx,
          y: cy,
          fill: '#FFFFFF',
          'font-size': '14',
          'font-weight': 'bold',
          'font-family': 'Courier New, monospace',
          'text-anchor': 'middle',
          'dominant-baseline': 'middle'
        });
        centerLabel.textContent = `${Math.round(avgValue)}%`;
        svg.appendChild(centerLabel);
      } else if (isExpanded) {
        // Expanded: number + "avg confidence" label
        centerLabel = createSvgElement('text', {
          x: cx,
          y: cy - 5,
          fill: '#FFFFFF',
          'font-size': '18',
          'font-weight': 'bold',
          'font-family': 'Courier New, monospace',
          'text-anchor': 'middle',
          'dominant-baseline': 'middle'
        });
        centerLabel.textContent = `${Math.round(avgValue)}%`;
        svg.appendChild(centerLabel);

        centerSublabel = createSvgElement('text', {
          x: cx,
          y: cy + 12,
          fill: '#64748B',
          'font-size': '9',
          'font-family': 'Inter, sans-serif',
          'text-anchor': 'middle'
        });
        centerSublabel.textContent = 'avg confidence';
        svg.appendChild(centerSublabel);
      }
    }

    // ── ANIMATION ───────────────────────────────────────────────────────────────
    const startTime = performance.now();
    const duration = opts.animationDuration;

    function animate(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1.0);

      // Easing function (ease-out cubic)
      const eased = 1 - Math.pow(1 - progress, 3);

      // Update polygon vertices
      const currentPoints = finalVertices.map((vertex, i) => {
        const x = lerp(cx, vertex.x, eased);
        const y = lerp(cy, vertex.y, eased);
        return `${x},${y}`;
      }).join(' ');

      dataPolygon.setAttribute('points', currentPoints);
      dataPolygon.setAttribute('fill-opacity', String(eased * opts.fillOpacity));

      // Update vertex dots
      vertexDots.forEach((dot, i) => {
        const vertex = finalVertices[i];
        dot.setAttribute('cx', String(lerp(cx, vertex.x, eased)));
        dot.setAttribute('cy', String(lerp(cy, vertex.y, eased)));
      });

      // Update value labels positions
      if (isExpanded && opts.showValues) {
        valueLabels.forEach((label, i) => {
          const vertex = finalVertices[i];
          // Position label slightly outside the vertex
          const angle = (2 * Math.PI * i) / numAxes;
          const labelRadius = radius * 0.85; // slightly inside
          const pos = polarToCartesian(cx, cy, labelRadius, angle);
          // Interpolate position
          label.setAttribute('x', String(lerp(cx, pos.x, eased)));
          label.setAttribute('y', String(lerp(cy, pos.y, eased)));
          label.style.opacity = String(eased);
        });
      }

      if (progress < 1.0) {
        requestAnimationFrame(animate);
      } else {
        // Animation complete - add subtle pulse effect
        dataPolygon.style.animation = 'pgRadarPulse 2s ease-in-out infinite';
        
        // Add pulse keyframes if not already present
        if (!document.getElementById('pg-radar-pulse-style')) {
          const style = document.createElement('style');
          style.id = 'pg-radar-pulse-style';
          style.textContent = `
            @keyframes pgRadarPulse {
              0%, 100% { transform: scale(1); transform-origin: center; }
              50% { transform: scale(1.02); transform-origin: center; }
            }
          `;
          document.head.appendChild(style);
        }
      }
    }

    requestAnimationFrame(animate);
  };
})();
