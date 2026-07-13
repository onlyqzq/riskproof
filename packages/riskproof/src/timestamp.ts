// ============================================================================
// RiskProof — Strict RFC 3339 timestamp parsing
// ============================================================================

const RFC3339_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-](\d{2}):(\d{2}))$/;

/** Parse the deterministic RFC 3339 subset used by engine and proof storage. */
export function parseRfc3339(value: unknown, label: string): number {
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be an RFC 3339 timestamp string`);
  }
  const match = RFC3339_PATTERN.exec(value);
  if (!match) throw new TypeError(`${label} must be a valid RFC 3339 timestamp`);

  const [, yearText, monthText, dayText, hourText, minuteText, secondText, , zone,
    offsetHourText, offsetMinuteText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const offsetHour = offsetHourText === undefined ? 0 : Number(offsetHourText);
  const offsetMinute = offsetMinuteText === undefined ? 0 : Number(offsetMinuteText);
  if (
    year < 1 || month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) ||
    hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59 ||
    (zone === "Z" && (offsetHourText !== undefined || offsetMinuteText !== undefined))
  ) {
    throw new TypeError(`${label} must be a valid RFC 3339 timestamp`);
  }

  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new TypeError(`${label} must be a valid RFC 3339 timestamp`);
  }
  return parsed;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}
