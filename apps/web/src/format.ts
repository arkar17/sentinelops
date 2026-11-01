import { ApiError } from "./api.ts";

export function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Something went wrong. Try again.";
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString();
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${String(seconds)} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${String(minutes)} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${String(hours)} h ${String(minutes % 60)} min`;
  return `${String(Math.floor(hours / 24))} d ${String(hours % 24)} h`;
}

/** Percentages never default to 100 %: missing data is shown as such. */
export function pct(value: number | null, digits = 2): string {
  return value === null ? "No data" : `${value.toFixed(digits)}%`;
}
