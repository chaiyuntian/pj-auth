export const readJsonBody = async <T>(request: Request): Promise<T | null> => {
  const raw = await request.text();
  if (!raw || !raw.trim()) {
    return null;
  }
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
};
