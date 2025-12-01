const API_TOKEN = import.meta.env.VITE_API_TOKEN || '';

export async function fetchWithAuth(url, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(API_TOKEN && { 'Authorization': `Bearer ${API_TOKEN}` }),
    ...options.headers
  };
  
  return fetch(url, { ...options, headers });
}
