export const nowIso = (): string => new Date().toISOString();

export const unixNow = (): number => Math.floor(Date.now() / 1000);

export const addSecondsToIso = (seconds: number): string => new Date(Date.now() + seconds * 1000).toISOString();

export const isIsoExpired = (isoValue: string): boolean => Date.parse(isoValue) <= Date.now();
