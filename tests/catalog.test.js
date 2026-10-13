'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { mount } = require('../controlplane/router');
const { CATALOG } = require('../routes/catalog');

// Record every route the control plane mounts without starting a server.
function mountedRoutes() {
  const seen = new Set();
  const app = {};
  for (const method of ['get', 'post', 'put', 'delete', 'patch', 'use', 'all']) {
    app[method] = (path) => {
      if (typeof path === 'string') seen.add(`${method.toUpperCase()} ${path}`);
    };
  }
  mount(app, {});
  return seen;
}

test('every endpoint the area index advertises is actually mounted', () => {
  const mounted = mountedRoutes();
  for (const [area, body] of Object.entries(CATALOG)) {
    assert.ok(body.endpoints.length > 0, `${area} lists nothing`);
    for (const line of body.endpoints) {
      const route = line.split(' - ')[0];
      assert.ok(mounted.has(route), `${area} advertises ${route}, which is not mounted`);
    }
  }
});
