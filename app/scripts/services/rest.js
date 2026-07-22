export function Api ($rootScope, $resource, config) {
  const roleShimCtx = {}

  // fetch API server details
  const protocol = config.protocol
  const host = config.host
  const hostPath = (config.hostPath || '').replace(/(^\/)|(\/$)/g, '')
  const port = config.port
  const server = protocol + '://' + host + ':' + port + (/^\s*$/.test(hostPath) ? '' : '/' + hostPath)

  const api = {
    Me: $resource(server + '/me'),

    AuthenticateLocal: $resource(server + '/authenticate/local', {}, {
      save: { method: 'POST' }
    }),

    AuthenticateOpenid: $resource(server + '/authenticate/openid', {}, {
      getToken: { method: 'POST' }
    }),

    Logout: $resource(server + '/logout'),

    AuthenticationTypes: $resource(`${server}/authentication/types`),

    Channels: $resource(server + '/channels/:channelId', { channelId: '@_id' }, {
      update: { method: 'PUT' },
      audits: {
        method: 'GET',
        url: server + '/channels/:channelId/audits',
        isArray: true
      }
    }),

    TriggerPollingChannels: $resource(server + '/channels/:channelId/trigger', { channelId: '@_id' }, {}),

    // OpenHIM Core v8 repurposed /roles for user RBAC roles and dropped the client-roles
    // API. Client roles are just strings on clients (roles[]) and channels (allow[]), so
    // emulate the old v7 endpoint on top of /clients and /channels. Same call shape as
    // the $resource it replaces: query(success, error) and update/save/remove(params,
    // body, success, error).
    Roles: clientRolesShim(),

    Users: $resource(server + '/users/:email', { email: '@email' }, {
      update: { method: 'PUT' }
    }),

    Clients: $resource(server + '/clients/:clientId/:property', { clientId: '@_id', property: '@property' }, {
      update: { method: 'PUT' }
    }),

    Transactions: $resource(server + '/transactions/:transactionId', { transactionId: '@_id' }),

    BulkReruns: $resource(server + '/bulkrerun'),

    Mediators: $resource(server + '/mediators/:urn', { urn: '@urn' }, {
      update: { method: 'PUT' }
    }),
    MediatorConfig: $resource(server + '/mediators/:urn/config', { urn: '@urn' }, {
      update: { method: 'PUT' }
    }),
    MediatorChannels: $resource(server + '/mediators/:urn/channels', { urn: '@urn' }),

    // add the metric endpoints
    MetricsChannels: $resource(server + '/metrics/channels/:channelId'),
    MetricsTimeseries: $resource(server + '/metrics/timeseries/:type'),
    MetricsTimeseriesChannel: $resource(server + '/metrics/timeseries/:type/channels/:channelId'),

    Tasks: $resource(server + '/tasks/:taskId', { taskId: '@_id' }, {
      update: { method: 'PUT' }
    }),

    ContactGroups: $resource(server + '/groups/:groupId', { groupId: '@_id' }, {
      update: { method: 'PUT' }
    }),

    Events: $resource(server + '/events/:receivedTime'),
    Heartbeat: $resource(server + '/heartbeat'),

    // endpoint to restart the core server
    Restart: $resource(server + '/restart', {}),

    // User Token
    UserPasswordToken: $resource(server + '/token/:token', { token: '@token' }, {
      update: { method: 'PUT' }
    }),

    // user reset password request
    UserPasswordResetRequest: $resource(server + '/password-reset-request/:email', { email: '@email' }, {}),

    Keystore: $resource(server + '/keystore/:type/:property', { type: '@type', property: '@property' }, {
      update: { method: 'PUT' }
    }),

    Certificates: $resource(server + '/certificates', {}),

    // ATNA Audit log endpoint
    Audits: $resource(server + '/audits/:auditId', { auditId: '@_id' }),
    AuditsFilterOptions: $resource(server + '/audits-filter-options/', {}),

    // Logs API
    Logs: $resource(server + '/logs'),

    // Metadata API
    Metadata: $resource(server + '/metadata', {}, {
      save: { method: 'POST', isArray: true },
      query: { method: 'GET', isArray: true }
    }),

    MetadataValidation: $resource(server + '/metadata/validate', {}, {
      save: { method: 'POST', isArray: true }
    }),

    // Visualizer API
    Visualizers: $resource(server + '/visualizers/:id', { id: '@_id' }, {
      update: { method: 'PUT' }
    }),

    // About page (versions) API
    About: $resource(server + '/about')

  }
  roleShimCtx.api = api
  return api

  function clientRolesShim () {
    const load = () => Promise.all([
      roleShimCtx.api.Clients.query().$promise,
      roleShimCtx.api.Channels.query().$promise
    ])

    const derive = (clients, channels) => {
      const roles = {}
      const get = name => (roles[name] = roles[name] || { name, clients: [], channels: [] })
      clients.forEach(c => (c.roles || []).forEach(r => get(r).clients.push({ _id: c._id, clientID: c.clientID, name: c.clientID })))
      channels.forEach(ch => (ch.allow || []).forEach(r => get(r).channels.push({ _id: ch._id, name: ch.name })))
      return Object.values(roles)
    }

    const wrap = (p, success, error) => p.then(r => { $rootScope.$applyAsync(); success && success(r) }, e => error && error(e.data ? e : { status: e.status || 500, data: String(e) }))

    // Set role membership: `want` lists the ids that should hold the role; everything
    // else loses it. `undefined` leaves that side untouched.
    const apply = async (name, clientsWanted, channelsWanted, rename) => {
      const [clients, channels] = await load()
      const ops = []
      const target = rename || name
      if (clientsWanted !== undefined || rename) {
        clients.forEach(c => {
          const has = (c.roles || []).includes(name)
          const want = clientsWanted === undefined ? has : clientsWanted.some(x => (x._id || x) === c._id)
          if (has === want && !(has && rename)) return
          const roles = (c.roles || []).filter(r => r !== name)
          if (want) roles.push(target)
          ops.push(roleShimCtx.api.Clients.update({ clientId: c._id }, { roles }).$promise)
        })
      }
      if (channelsWanted !== undefined || rename) {
        channels.forEach(ch => {
          const has = (ch.allow || []).includes(name)
          const want = channelsWanted === undefined ? has : channelsWanted.some(x => (x._id || x) === ch._id)
          if (has === want && !(has && rename)) return
          const allow = (ch.allow || []).filter(r => r !== name)
          if (want) allow.push(target)
          ops.push(roleShimCtx.api.Channels.update({ channelId: ch._id }, { allow }).$promise)
        })
      }
      await Promise.all(ops)
    }

    return {
      query: (success, error) => {
        const out = []
        wrap(load().then(([c, ch]) => { out.push(...derive(c, ch)); return out }), success, error)
        return out
      },
      get: (params, success, error) => wrap(load().then(([c, ch]) => derive(c, ch).find(r => r.name === params.name)), success, error),
      update: (params, body, success, error) => wrap(apply(params.name, body.clients, body.channels, body.name), success, error),
      save: (params, body, success, error) => wrap(apply(body.name, body.clients || [], body.channels || []), success, error),
      remove: (params, body, success, error) => wrap(apply(params.name, [], []), success, error)
    }
  }
}
