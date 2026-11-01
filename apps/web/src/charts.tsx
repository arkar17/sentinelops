import { useState } from "react";

/**
 * Dependency-free SVG charts. Series colors come from CSS tokens (validated palette, light and
 * dark steps). Every chart has a text alternative: an aria-label summary plus a table view.
 */

export interface LatencyPoint {
  label: string;
  p50: number | null;
  p95: number | null;
}

export interface UptimePoint {
  label: string;
  uptime: number | null;
  samples: number;
}

const W = 640;
const H = 200;
const PAD = { top: 12, right: 56, bottom: 24, left: 44 };

function scaleY(value: number, max: number): number {
  return PAD.top + (H - PAD.top - PAD.bottom) * (1 - value / max);
}

function niceMax(values: number[]): number {
  const max = Math.max(1, ...values);
  const magnitude = 10 ** Math.floor(Math.log10(max));
  return Math.ceil(max / magnitude) * magnitude;
}

function path(points: (number | null)[], x: (i: number) => number, max: number): string {
  let d = "";
  let pen = false;
  points.forEach((value, i) => {
    if (value === null) {
      pen = false;
      return;
    }
    d += `${pen ? "L" : "M"}${x(i).toFixed(1)},${scaleY(value, max).toFixed(1)}`;
    pen = true;
  });
  return d;
}

function TableView({ caption, head, rows }: { caption: string; head: string[]; rows: string[][] }) {
  return (
    <details className="chart-table">
      <summary>Show as table</summary>
      <table tabIndex={0}>
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr>
            {head.map((h) => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row[0]}>
              {row.map((cell, i) => (
                <td key={`${row[0] ?? ""}-${String(i)}`}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}

const ms = (v: number | null) => (v === null ? "—" : `${String(v)} ms`);
const pct = (v: number | null) => (v === null ? "No data" : `${v.toFixed(2)}%`);

export function LatencyChart({ title, points }: { title: string; points: LatencyPoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  if (points.length === 0) return <p className="muted">No response-time data for this period.</p>;
  const max = niceMax(points.flatMap((p) => [p.p50 ?? 0, p.p95 ?? 0]));
  const step = (W - PAD.left - PAD.right) / Math.max(1, points.length - 1);
  const x = (i: number) => PAD.left + i * step;
  const lastWith = (key: "p50" | "p95") => {
    for (let i = points.length - 1; i >= 0; i -= 1) {
      const v = points[i]?.[key];
      if (v != null) return { i, v };
    }
    return null;
  };
  const end50 = lastWith("p50");
  const end95 = lastWith("p95");
  const active = hover !== null ? points[hover] : undefined;
  return (
    <figure className="chart">
      <figcaption>{title}</figcaption>
      <div className="legend" aria-hidden="true">
        <span>
          <i className="swatch series-1" /> Median (p50)
        </span>
        <span>
          <i className="swatch series-2" /> 95th percentile (p95)
        </span>
      </div>
      <div className="chart-frame">
        <svg
          viewBox={`0 0 ${String(W)} ${String(H)}`}
          role="img"
          aria-label={`${title}. Latest median ${ms(end50?.v ?? null)}, latest 95th percentile ${ms(end95?.v ?? null)}.`}
          onMouseLeave={() => {
            setHover(null);
          }}
        >
          {[0, 0.5, 1].map((f) => (
            <g key={f}>
              <line className="grid" x1={PAD.left} x2={W - PAD.right} y1={scaleY(max * f, max)} y2={scaleY(max * f, max)} />
              <text className="axis" x={PAD.left - 6} y={scaleY(max * f, max) + 4} textAnchor="end">
                {Math.round(max * f)}
              </text>
            </g>
          ))}
          <path className="line series-1" d={path(points.map((p) => p.p50), x, max)} />
          <path className="line series-2" d={path(points.map((p) => p.p95), x, max)} />
          {end50 && (
            <text className="direct-label" x={x(end50.i) + 6} y={scaleY(end50.v, max) + 4}>
              p50
            </text>
          )}
          {end95 && (
            <text className="direct-label" x={x(end95.i) + 6} y={scaleY(end95.v, max) - 4}>
              p95
            </text>
          )}
          {hover !== null && active && (
            <g>
              <line className="crosshair" x1={x(hover)} x2={x(hover)} y1={PAD.top} y2={H - PAD.bottom} />
              {active.p50 !== null && <circle className="dot series-1" cx={x(hover)} cy={scaleY(active.p50, max)} r={4} />}
              {active.p95 !== null && <circle className="dot series-2" cx={x(hover)} cy={scaleY(active.p95, max)} r={4} />}
            </g>
          )}
          {points.map((p, i) => (
            <rect
              key={p.label}
              className="hit"
              x={x(i) - step / 2}
              y={PAD.top}
              width={Math.max(step, 6)}
              height={H - PAD.top - PAD.bottom}
              onMouseEnter={() => {
                setHover(i);
              }}
            />
          ))}
          <text className="axis" x={PAD.left} y={H - 6}>
            {points[0]?.label}
          </text>
          <text className="axis" x={W - PAD.right} y={H - 6} textAnchor="end">
            {points[points.length - 1]?.label}
          </text>
        </svg>
        {active && (
          <div className="tooltip" role="status">
            <strong>{active.label}</strong>
            <span>p50 {ms(active.p50)}</span>
            <span>p95 {ms(active.p95)}</span>
          </div>
        )}
      </div>
      <TableView
        caption={title}
        head={["Period", "Median", "95th percentile"]}
        rows={points.map((p) => [p.label, ms(p.p50), ms(p.p95)])}
      />
    </figure>
  );
}

export function UptimeChart({ title, points }: { title: string; points: UptimePoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  if (points.length === 0) return <p className="muted">No checks in this period.</p>;
  const values = points.map((p) => p.uptime).filter((v): v is number => v !== null);
  const floor = values.length > 0 && Math.min(...values) >= 90 ? 90 : 0;
  const slot = (W - PAD.left - PAD.right) / points.length;
  const bar = Math.max(2, slot - 2);
  const y = (v: number) => scaleY(v - floor, 100 - floor);
  const active = hover !== null ? points[hover] : undefined;
  return (
    <figure className="chart">
      <figcaption>{title}</figcaption>
      <div className="chart-frame">
        <svg
          viewBox={`0 0 ${String(W)} ${String(H)}`}
          role="img"
          aria-label={`${title}. ${String(values.length)} of ${String(points.length)} periods have data${
            values.length ? `; lowest ${Math.min(...values).toFixed(2)}%` : ""
          }.`}
          onMouseLeave={() => {
            setHover(null);
          }}
        >
          <defs>
            <pattern id="nodata" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
              <line x1="0" y1="0" x2="0" y2="6" className="hatch" />
            </pattern>
          </defs>
          {[floor, (floor + 100) / 2, 100].map((v) => (
            <g key={v}>
              <line className="grid" x1={PAD.left} x2={W - PAD.right} y1={y(v)} y2={y(v)} />
              <text className="axis" x={PAD.left - 6} y={y(v) + 4} textAnchor="end">
                {`${String(v)}%`}
              </text>
            </g>
          ))}
          {points.map((p, i) => {
            const left = PAD.left + i * slot + 1;
            const top = p.uptime === null ? PAD.top : y(p.uptime);
            return (
              <g key={p.label}>
                <rect
                  className={p.uptime === null ? "bar nodata" : "bar series-1"}
                  x={left}
                  y={top}
                  width={bar}
                  height={Math.max(0, H - PAD.bottom - top)}
                  rx={Math.min(4, bar / 2)}
                />
                <rect
                  className="hit"
                  x={left - 1}
                  y={PAD.top}
                  width={slot}
                  height={H - PAD.top - PAD.bottom}
                  onMouseEnter={() => {
                    setHover(i);
                  }}
                />
              </g>
            );
          })}
          <text className="axis" x={PAD.left} y={H - 6}>
            {points[0]?.label}
          </text>
          <text className="axis" x={W - PAD.right} y={H - 6} textAnchor="end">
            {points[points.length - 1]?.label}
          </text>
        </svg>
        {active && (
          <div className="tooltip" role="status">
            <strong>{active.label}</strong>
            <span>Uptime {pct(active.uptime)}</span>
            <span>{active.samples} conclusive checks</span>
          </div>
        )}
      </div>
      <p className="hint">Hatched bars: no conclusive checks (a coverage gap, not downtime).</p>
      <TableView
        caption={title}
        head={["Period", "Uptime", "Conclusive checks"]}
        rows={points.map((p) => [p.label, pct(p.uptime), String(p.samples)])}
      />
    </figure>
  );
}

export interface Slice {
  key: string;
  label: string;
  value: number;
  tone: "good" | "warning" | "critical" | "neutral";
}

/** Part-to-whole bar for monitor health; status colors always paired with a text label. */
export function DistributionBar({ title, slices }: { title: string; slices: Slice[] }) {
  const total = slices.reduce((sum, s) => sum + s.value, 0);
  return (
    <figure className="chart">
      <figcaption>{title}</figcaption>
      {total === 0 ? (
        <p className="muted">No active monitors.</p>
      ) : (
        <div
          className="distribution"
          role="img"
          aria-label={`${title}: ${slices.map((s) => `${s.label} ${String(s.value)}`).join(", ")}`}
        >
          {slices
            .filter((s) => s.value > 0)
            .map((s) => (
              <span
                key={s.key}
                className={`segment tone-${s.tone}`}
                style={{ flexGrow: s.value }}
                title={`${s.label}: ${String(s.value)}`}
              />
            ))}
        </div>
      )}
      <ul className="legend plain">
        {slices.map((s) => (
          <li key={s.key}>
            <i className={`swatch tone-${s.tone}`} /> {s.label}: <strong>{s.value}</strong>
          </li>
        ))}
      </ul>
    </figure>
  );
}
