# SystemAPI dashboard

React + Vite single-page app for the SystemAPI control plane. It talks to the
`/api/v1` routes served by `server.js` in the repo root.

```
npm ci
npm run dev      # local dev server
npm run build    # production bundle in dist/
npm run lint
npm test         # node --test over the pure display helpers in src/format.js
```

Set `VITE_API_URL` when the API is not on the same origin.
