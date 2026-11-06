// Run: yarn babel-node test/member-gql-gate.test.js
// Starts the real express app against a local stub upstream. No network
// request leaves this machine.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { after, before, beforeEach, describe, it } from 'node:test'
import zlib from 'node:zlib'
import jwt from 'jsonwebtoken'
import { createApp } from '../src/app'

const adam = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, 'fixtures/adam-member-operations.json'),
    'utf8'
  )
)

const jwtSecret = 'test-secret'
const internalApiKey = 'test-internal-key'
const uid = 'uid-self'
const scope = `read:posts read:member-info:${uid} write:member-info:${uid}`
const token = jwt.sign({ sub: `mirror-weekly|${uid}`, scope }, jwtSecret, {
  expiresIn: 600,
})
const expiredToken = jwt.sign(
  { sub: `mirror-weekly|${uid}`, scope },
  jwtSecret,
  { expiresIn: -10 }
)
const forgedToken = jwt.sign(
  { sub: `mirror-weekly|${uid}`, scope },
  'other-secret'
)
const noSubToken = jwt.sign({ scope }, jwtSecret)

const received = []
let upstream
let server
let base

const listen = (handler) =>
  new Promise((resolve) => {
    const s = http
      .createServer(handler)
      .listen(0, '127.0.0.1', () => resolve(s))
  })

before(async () => {
  upstream = await listen((req, res) => {
    let raw = ''
    req.on('data', (chunk) => (raw += chunk))
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json')
      if (raw.includes('authenticateuserWithPassword')) {
        res.end(
          JSON.stringify({
            data: { authenticateuserWithPassword: { sessionToken: 'stub' } },
          })
        )
        return
      }
      received.push({ headers: req.headers, url: req.url, raw })
      res.end(JSON.stringify({ data: { stub: true } }))
    })
  })
  const origin = `http://127.0.0.1:${upstream.address().port}`
  const app = createApp({
    gcpProjectId: 'test',
    firebaseProjectId: 'test',
    jwtSecret,
    jwtLifeTime: 3600,
    weeklyProxyOrigin: origin,
    israfelProxyOrigin: origin,
    gcsProxyOrigin: origin,
    youtubeProxyOrigin: origin,
    corsAllowOrigin: '*',
    israfelHeadlessAccount: { email: 'a@b', password: 'p' },
    contentGQLHeadlessAccount: { email: 'a@b', password: 'p' },
    bypassAuthorization: false,
    internalApiKey,
  })
  server = await listen(app)
  base = `http://127.0.0.1:${server.address().port}`
})

after(() => {
  server.close()
  upstream.close()
})

beforeEach(() => {
  received.length = 0
})

const asUser = { authorization: `Bearer ${token}` }
const asInternal = { 'x-internal-api-key': internalApiKey }

function post(body, headers = {}, url = '/member/graphql') {
  return fetch(base + url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

async function expectForwarded(body, headers) {
  const res = await post(body, headers)
  assert.equal(res.status, 200)
  assert.equal(received.length, 1)
  return received[0]
}

async function expectBlocked(body, headers, status = 403, url) {
  const res = await post(body, headers, url)
  assert.equal(res.status, status)
  assert.equal(received.length, 0, 'request reached the upstream')
}

const orderData = {
  merchandise: { connect: { code: 'magazine_one_year' } },
  itemCount: 1,
  purchaseDatetime: '2026-11-04T00:00:00.000Z',
  purchaseName: 'n',
  purchaseAddress: 'a',
  purchaseEmail: 'e@example.test',
  receiveName: 'n',
  receiveAddress: 'a',
  category: 'B2C',
}

describe('legitimate callers, documents as printed by Apollo Client', () => {
  const cases = [
    ['fetchAllMember', { firebaseId: uid }, asUser, 'read:member-info'],
    ['fetchMemberProfile', { firebaseId: uid }, asUser, 'read:member-info'],
    [
      'createMember',
      { firebaseId: uid, email: 'n@example.test' },
      asUser,
      'read:member-info',
    ],
    [
      'updateMember',
      {
        id: '42',
        name: 'n',
        gender: 'M',
        birthday: '2000-01-01',
        phone: '0900',
        country: 'TW',
        city: 'c',
        district: 'd',
        address: 'a',
      },
      asUser,
      'read:member-info',
    ],
    ['magazineOrder', { orderNumber: 'P2026110412345' }, asInternal, ''],
    ['fetchPaymentDataOfPapermag', { data: orderData }, asInternal, ''],
  ]

  for (const [name, variables, headers, expectedScope] of cases) {
    it(`forwards ${name} with session, scope and exact variables`, async () => {
      const seen = await expectForwarded(
        { operationName: name, variables, query: adam[name] },
        headers
      )
      assert.equal(seen.url, '/api/graphql')
      assert.equal(seen.headers.cookie, 'keystonejs-session=stub')
      assert.equal(seen.headers['x-internal-api-key'], undefined)
      assert.equal(seen.headers.authorization, undefined)
      assert.ok(
        seen.headers['x-access-token-scope'].includes(expectedScope),
        'scope header'
      )
      const forwarded = JSON.parse(seen.raw)
      assert.deepEqual(forwarded.variables, variables)
      assert.equal(forwarded.operationName, name)
      assert.equal(
        Number(seen.headers['content-length']),
        Buffer.byteLength(seen.raw)
      )
    })
  }

  it('forwards a gzip encoded body after decoding it', async () => {
    const body = zlib.gzipSync(
      JSON.stringify({
        variables: { firebaseId: uid },
        query: adam.fetchAllMember,
      })
    )
    const res = await fetch(base + '/member/graphql', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-encoding': 'gzip',
        ...asUser,
      },
      body,
    })
    assert.equal(res.status, 200)
    assert.equal(received[0].headers['content-encoding'], undefined)
    assert.equal(JSON.parse(received[0].raw).variables.firebaseId, uid)
  })

  it('accepts literal firebaseId equal to the token', async () => {
    await expectForwarded(
      { query: `{ member(where: { firebaseId: "${uid}" }) { id } }` },
      asUser
    )
  })

  it('leaves /content/graphql streaming and anonymous', async () => {
    const res = await post(
      { query: '{ posts { id } }' },
      {},
      '/content/graphql'
    )
    assert.equal(res.status, 200)
    assert.equal(JSON.parse(received[0].raw).query, '{ posts { id } }')
  })
})

describe('identity', () => {
  const profile = {
    variables: { firebaseId: uid },
    query: adam.fetchAllMember,
  }
  const order = {
    variables: { orderNumber: 'P1' },
    query: adam.magazineOrder,
  }

  it('rejects anonymous', () => expectBlocked(profile, {}, 401))
  it('rejects an empty authorization header', () =>
    expectBlocked(
      profile,
      { authorization: '', 'x-internal-api-key': '' },
      401
    ))
  it('rejects expired', () =>
    expectBlocked(profile, { authorization: `Bearer ${expiredToken}` }, 401))
  it('rejects forged', () =>
    expectBlocked(profile, { authorization: `Bearer ${forgedToken}` }, 401))
  it('rejects a token with no subject', () =>
    expectBlocked(profile, { authorization: `Bearer ${noSubToken}` }, 401))
  it('rejects a wrong key', () =>
    expectBlocked(order, { 'x-internal-api-key': 'nope' }, 401))
  it('rejects a user token on internal operations', () =>
    expectBlocked(order, asUser))
  it('rejects the key on user operations', () =>
    expectBlocked(profile, asInternal))
  it('ignores a client supplied scope and cookie', async () => {
    const seen = await expectForwarded(profile, {
      ...asUser,
      'x-access-token-scope': 'read:member-info:victim',
      cookie: 'keystonejs-session=evil',
    })
    assert.equal(seen.headers['x-access-token-scope'], scope)
    assert.equal(seen.headers.cookie, 'keystonejs-session=stub')
  })
})

describe('rejected as a token holder', () => {
  const rejected = {
    'list root field': '{ members { id email } }',
    'list root field with filter':
      '{ members(where: { firebaseId: { equals: "uid-self" } }) { id } }',
    count: '{ membersCount }',
    'orders list':
      '{ magazineOrders(where: { orderNumber: { equals: "P1" } }) { id } }',
    'payment list': '{ newebpayPayments { id } }',
    users: '{ users { email } }',
    subscriptions: '{ subscriptions { id } }',
    'authenticated item': '{ authenticatedItem { __typename } }',
    'schema introspection': '{ __schema { types { name } } }',
    'type introspection': '{ __type(name: "member") { name } }',
    'root __typename': '{ __typename }',
    'keystone meta': '{ keystone { adminMeta { lists { key } } } }',
    alias: '{ a: member(where: { firebaseId: "uid-self" }) { id } }',
    'alias of a list': '{ member: members { id } }',
    'second root field':
      '{ member(where: { firebaseId: "uid-self" }) { id } members { id } }',
    'root fragment spread': '{ ...F } fragment F on Query { members { id } }',
    'root inline fragment': '{ ... on Query { members { id } } }',
    'nested fragment':
      '{ member(where: { firebaseId: "uid-self" }) { ...M } } fragment M on member { group { id } }',
    'nested inline fragment':
      '{ member(where: { firebaseId: "uid-self" }) { ... on member { group { id } } } }',
    'nested relationship':
      '{ member(where: { firebaseId: "uid-self" }) { subscription { id } } }',
    'nested alias':
      '{ member(where: { firebaseId: "uid-self" }) { x: email } }',
    'nested arguments':
      '{ member(where: { firebaseId: "uid-self" }) { email(a: 1) } }',
    'field not on the list':
      '{ member(where: { firebaseId: "uid-self" }) { type } }',
    'inherited key':
      '{ member(where: { firebaseId: "uid-self" }) { constructor } }',
    'inherited root key': '{ constructor }',
    directive:
      '{ member(where: { firebaseId: "uid-self" }) @include(if: true) { id } }',
    'nested directive':
      '{ member(where: { firebaseId: "uid-self" }) { id @skip(if: true) } }',
    'other member by firebaseId':
      '{ member(where: { firebaseId: "victim" }) { id email } }',
    'member by email': '{ member(where: { email: "v@example.test" }) { id } }',
    'member by id': '{ member(where: { id: "1" }) { id } }',
    'two where keys':
      '{ member(where: { firebaseId: "uid-self", email: "x" }) { id } }',
    'extra argument':
      '{ member(where: { firebaseId: "uid-self" }, take: 5) { id } }',
    'no selection': '{ member(where: { firebaseId: "uid-self" }) }',
    'default variable':
      'query($f: String = "victim") { member(where: { firebaseId: $f }) { id } }',
    'two operations':
      'query A { member(where: { firebaseId: "uid-self" }) { id } } query B { members { id } }',
    'subscription operation':
      'subscription { member(where: { firebaseId: "uid-self" }) { id } }',
    'mutation wrapper on a query field':
      'mutation { member(where: { firebaseId: "uid-self" }) { id } }',
    'set own type':
      'mutation { updatemember(where: { id: "1" }, data: { type: subscribe_yearly }) { name } }',
    'set own email':
      'mutation { updatemember(where: { id: "1" }, data: { email: "x@example.test" }) { name } }',
    'create for another uid':
      'mutation { createmember(data: { firebaseId: "victim", email: "x" }) { id } }',
    'create with extra field':
      'mutation { createmember(data: { firebaseId: "uid-self", email: "x", type: marketing }) { id } }',
    'bulk update': 'mutation { updateMembers(data: []) { id } }',
    'create subscription': 'mutation { createsubscription(data: {}) { id } }',
    'password login':
      'mutation { authenticateuserWithPassword(email: "a", password: "b") { __typename } }',
    'end session': 'mutation { endSession }',
    'internal mutation':
      'mutation { createNewebpayTradeInfoForMagazineOrder(data: {}) { Amt } }',
    'comment hiding a list':
      '#{ member(where: { firebaseId: "uid-self" }) { id } }\n{ members { id } }',
    'block string decoy':
      '{ members(search: """member(where: { firebaseId: "uid-self" })""") { id } }',
    unparseable: '{ member(',
    'empty document': '',
  }

  for (const [name, query] of Object.entries(rejected)) {
    it(name, () => expectBlocked({ query }, asUser))
  }

  it('where passed by variable for another uid', () =>
    expectBlocked(
      {
        query:
          'query($w: memberWhereUniqueInput!) { member(where: $w) { id } }',
        variables: { w: { firebaseId: 'victim' } },
      },
      asUser
    ))
  it('array in a variable', () =>
    expectBlocked(
      { query: adam.fetchAllMember, variables: { firebaseId: [uid] } },
      asUser
    ))
  it('data passed by variable with a forbidden key', () =>
    expectBlocked(
      {
        query:
          'mutation($d: memberUpdateInput!) { updatemember(where: { id: "1" }, data: $d) { name } }',
        variables: { d: { type: 'marketing' } },
      },
      asUser
    ))
  it('variables that are not an object', () =>
    expectBlocked({ query: adam.fetchAllMember, variables: [uid] }, asUser))
  it('operationName that does not match', () =>
    expectBlocked(
      {
        query: adam.fetchAllMember,
        operationName: 'other',
        variables: { firebaseId: uid },
      },
      asUser
    ))
  it('batched array', () =>
    expectBlocked(
      [{ query: adam.fetchAllMember, variables: { firebaseId: uid } }],
      asUser
    ))
  it('persisted query with no document', () =>
    expectBlocked(
      {
        extensions: {
          persistedQuery: { version: 1, sha256Hash: 'a'.repeat(64) },
        },
      },
      asUser
    ))
  it('non JSON body', () =>
    expectBlocked('{ members { id } }', {
      ...asUser,
      'content-type': 'application/graphql',
    }))
  it('form body', () =>
    expectBlocked('query=%7Bmembers%7Bid%7D%7D', {
      ...asUser,
      'content-type': 'application/x-www-form-urlencoded',
    }))
  it('malformed JSON', () => expectBlocked('{', asUser, 400))
  it('body over the limit', () =>
    expectBlocked(
      {
        query: adam.fetchAllMember,
        variables: { firebaseId: uid, pad: 'x'.repeat(70000) },
      },
      asUser,
      400
    ))
  it('query over the token limit', () =>
    expectBlocked(
      {
        query: `{ member(where: { firebaseId: "uid-self" }) { ${'id '.repeat(
          3000
        )} } }`,
      },
      asUser
    ))
  it('query string on POST', () =>
    expectBlocked(
      { query: adam.fetchAllMember, variables: { firebaseId: uid } },
      asUser,
      400,
      '/member/graphql?query=%7Bmembers%7Bid%7D%7D'
    ))
})

describe('forwarded body', () => {
  it('sends the printed document, not the original body', async () => {
    const query = `# ignored comment\n${adam.fetchAllMember}`
    const forwarded = await expectForwarded(
      { query, variables: { firebaseId: uid }, extra: 'dropped' },
      asUser
    )
    const body = JSON.parse(forwarded.raw)
    assert.equal(body.query.includes('ignored comment'), false)
    assert.equal('extra' in body, false)
  })
})

describe('rejected with the internal key', () => {
  const rejected = {
    'list of members': '{ members { email } }',
    'orders without a filter': '{ magazineOrders { id purchaseEmail } }',
    'orders with take':
      '{ magazineOrders(where: { orderNumber: { equals: "P1" } }, take: 1000) { id } }',
    'orders by another field':
      '{ magazineOrders(where: { purchaseEmail: { equals: "x" } }) { id } }',
    'orders with a contains filter':
      '{ magazineOrders(where: { orderNumber: { contains: "P" } }) { id } }',
    'orders with a field outside the tree':
      '{ magazineOrders(where: { orderNumber: { equals: "P1" } }) { invoice { id } } }',
  }
  for (const [name, query] of Object.entries(rejected)) {
    it(name, () => expectBlocked({ query }, asInternal))
  }
})

describe('path and method variants', () => {
  it('answers the CORS preflight without the gate', async () => {
    const res = await fetch(`${base}/member/graphql`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://www.mirrormedia.mg',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'authorization,content-type',
      },
    })
    assert.equal(res.status, 204)
    assert.equal(received.length, 0)
  })

  const list = { query: '{ members { id } }' }
  for (const url of [
    '/MEMBER/GRAPHQL',
    '/member/graphql/',
    '/Member/Graphql/',
  ]) {
    it(`POST ${url} goes through the gate`, () =>
      expectBlocked(list, {}, 401, url))
  }
  for (const url of [
    '/member/graphql/x',
    '/member%2Fgraphql',
    '/member/graphq%6C',
    '//member/graphql',
  ]) {
    it(`POST ${url} never reaches the upstream`, async () => {
      const res = await post(list, asUser, url)
      assert.notEqual(res.status, 200)
      assert.equal(received.length, 0)
    })
  }
  for (const method of ['GET', 'PUT', 'PATCH', 'DELETE']) {
    it(`${method} never reaches the upstream`, async () => {
      const res = await fetch(
        `${base}/member/graphql?query=%7Bmembers%7Bid%7D%7D`,
        {
          method,
          headers: asUser,
        }
      )
      assert.notEqual(res.status, 200)
      assert.equal(received.length, 0)
    })
  }
})
