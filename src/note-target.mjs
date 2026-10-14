const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

// Select the resource from the actual API pathname, never Vercel's merged query object.
export function noteTarget(request) {
  if (typeof request.url !== 'string') return null;
  let url;
  try { url = new URL(request.url, 'https://api.invalid'); } catch { return null; }
  const segments = url.pathname.split('/');
  if (segments.length !== 4 || segments[1] !== 'api' || segments[2] !== 'notes'
      || !UUID.test(segments[3])) return null;
  const id = segments[3].toLowerCase();
  for (const key of url.searchParams.keys()) if (key !== 'id') return null;
  const selectors = url.searchParams.getAll('id');
  if (selectors.length > 1 || selectors.some(value => value.toLowerCase() !== id)) return null;
  return id;
}
