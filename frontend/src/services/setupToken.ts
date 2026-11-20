// First-run setup token handed over by the desktop app (see lsadra/api/setup.py).
// The app opens the dashboard at `/?setup_token=<random>`; this keeps the token
// for this window only (sessionStorage) and removes it from the address.
// Kept free of imports so it can be unit-tested with plain `node --test`.

export const SETUP_TOKEN_KEY = 'lsadra_setup_token';
const PARAM = 'setup_token';

/** The setup token in a query string, or null. Only plain token characters. */
export const tokenFromSearch = (search: string): string | null => {
  const value = new URLSearchParams(search).get(PARAM);
  return value && /^[A-Za-z0-9_-]{32,256}$/.test(value) ? value : null;
};

/** The query string with the setup token removed ('' when nothing is left). */
export const searchWithoutToken = (search: string): string => {
  const params = new URLSearchParams(search);
  params.delete(PARAM);
  const rest = params.toString();
  return rest ? `?${rest}` : '';
};

interface Place {
  location: { search: string; pathname: string; hash: string };
  history: { replaceState: (data: unknown, unused: string, url: string) => void };
  sessionStorage: { setItem: (k: string, v: string) => void };
}

/** Move a token from the address bar into sessionStorage. Call before routing. */
export const captureSetupToken = (w: Place): void => {
  const token = tokenFromSearch(w.location.search);
  if (!new URLSearchParams(w.location.search).has(PARAM)) return;
  if (token) w.sessionStorage.setItem(SETUP_TOKEN_KEY, token);
  w.history.replaceState(null, '', w.location.pathname + searchWithoutToken(w.location.search) + w.location.hash);
};
