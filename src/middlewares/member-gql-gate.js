import crypto from 'crypto'
import express from 'express'
import { Kind, parse, print, valueFromASTUntyped } from 'graphql'
import { statusCodes } from '../constants'
import { verifyAccessToken } from './auth'

const CALLER = { user: 'user', internal: 'internal' }

const hasOnlyKeys = (value, allowed) =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).every((key) => allowed.includes(key))

const isPlainObject = (value) => hasOnlyKeys(value, Object.keys(value ?? {}))

const isNonEmptyString = (value) => typeof value === 'string' && value !== ''

const flat = (...names) => Object.fromEntries(names.map((n) => [n, true]))

const MEMBER_EDITABLE_FIELDS = [
  'phone',
  'gender',
  'birthday',
  'name',
  'address',
  'city',
  'country',
  'district',
]

/**
 * The only root fields reachable through `/member/graphql`. Every other root
 * field, including list fields, counts and introspection, is rejected.
 * `selection` is the complete tree of selectable fields under the root.
 */
const ROOT_FIELD_RULES = {
  member: {
    operation: 'query',
    caller: CALLER.user,
    selection: flat(
      'id',
      'firebaseId',
      'email',
      'name',
      'gender',
      'birthday',
      'phone',
      'country',
      'city',
      'district',
      'address'
    ),
    argNames: ['where'],
    allowArgs: ({ where }, uid) =>
      hasOnlyKeys(where, ['firebaseId']) && where.firebaseId === uid,
  },
  createmember: {
    operation: 'mutation',
    caller: CALLER.user,
    selection: flat('id', 'firebaseId'),
    argNames: ['data'],
    allowArgs: ({ data }, uid, email) =>
      hasOnlyKeys(data, ['firebaseId', 'email']) &&
      data.firebaseId === uid &&
      isNonEmptyString(data.email) &&
      isNonEmptyString(email) &&
      data.email.toLowerCase() === email.toLowerCase(),
  },
  // Israfel's `member` update filter limits the target to the caller's own
  // record, using the firebaseId in `X-Access-Token-Scope`.
  updatemember: {
    operation: 'mutation',
    caller: CALLER.user,
    selection: flat(...MEMBER_EDITABLE_FIELDS),
    argNames: ['where', 'data'],
    allowArgs: ({ where, data }) =>
      hasOnlyKeys(where, ['id']) &&
      isNonEmptyString(where.id) &&
      hasOnlyKeys(data, MEMBER_EDITABLE_FIELDS),
  },
  magazineOrders: {
    operation: 'query',
    caller: CALLER.internal,
    selection: {
      ...flat(
        'id',
        'orderNumber',
        'purchaseDatetime',
        'itemCount',
        'totalAmount',
        'purchaseName',
        'purchaseEmail',
        'purchaseMobile',
        'receiveName',
        'receiveMobile',
        'receiveAddress',
        'createdAt',
        'promoteCode'
      ),
      merchandise: flat('name', 'code', 'price'),
    },
    argNames: ['where'],
    allowArgs: ({ where }) =>
      hasOnlyKeys(where, ['orderNumber']) &&
      hasOnlyKeys(where.orderNumber, ['equals']) &&
      isNonEmptyString(where.orderNumber.equals),
  },
  createNewebpayTradeInfoForMagazineOrder: {
    operation: 'mutation',
    caller: CALLER.internal,
    selection: flat(
      'MerchantID',
      'RespondType',
      'TimeStamp',
      'Version',
      'MerchantOrderNo',
      'Amt',
      'ItemDesc',
      'LoginType',
      'Email',
      'TradeLimit',
      'NotifyURL'
    ),
    argNames: ['data'],
    allowArgs: ({ data }) => isPlainObject(data),
  },
}

/**
 * Walk a selection set against the allowed tree. Fragments, aliases,
 * directives and nested arguments are all refused: none of them are used by
 * the known callers, and each of them can hide what is really selected.
 * @param {import('graphql').SelectionSetNode} selectionSet
 * @param {Object} allowed
 * @returns {boolean}
 */
function isSelectionAllowed(selectionSet, allowed) {
  return selectionSet.selections.every((node) => {
    if (
      node.kind !== Kind.FIELD ||
      node.alias ||
      node.directives?.length ||
      node.arguments?.length
    ) {
      return false
    }
    const name = node.name.value
    if (name === '__typename') {
      return !node.selectionSet
    }
    if (!Object.hasOwn(allowed, name)) {
      return false
    }
    const child = allowed[name]
    if (child === true) {
      return !node.selectionSet
    }
    return !!node.selectionSet && isSelectionAllowed(node.selectionSet, child)
  })
}

/**
 * Decide whether a request body is allowed, using the same grammar the
 * backend executes (graphql-js `parse`).
 * @param {unknown} body
 * @param {{ caller: string, uid?: string, email?: string }} identity
 * @returns {{ reason: string, rootField?: string } | { forwardBody: string }}
 */
export function evaluateMemberRequest(body, { caller, uid, email }) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { reason: 'body-not-single-object' }
  }
  const { query, variables, operationName } = body
  if (typeof query !== 'string') {
    return { reason: 'query-missing' }
  }
  if (
    variables !== undefined &&
    variables !== null &&
    (typeof variables !== 'object' || Array.isArray(variables))
  ) {
    return { reason: 'variables-not-object' }
  }

  let document
  try {
    document = parse(query, { noLocation: true, maxTokens: 2000 })
  } catch (err) {
    return { reason: 'query-unparseable' }
  }

  const [operation] = document.definitions
  if (
    document.definitions.length !== 1 ||
    operation.kind !== Kind.OPERATION_DEFINITION ||
    operation.directives?.length
  ) {
    return { reason: 'not-single-operation' }
  }
  if (operationName && operationName !== operation.name?.value) {
    return { reason: 'operation-name-mismatch' }
  }

  const { selections } = operation.selectionSet
  const [root] = selections
  if (
    selections.length !== 1 ||
    root.kind !== Kind.FIELD ||
    root.alias ||
    root.directives?.length
  ) {
    return { reason: 'not-single-root-field' }
  }

  const rootField = root.name.value.slice(0, 64)
  if (!Object.hasOwn(ROOT_FIELD_RULES, root.name.value)) {
    return { reason: 'root-field-not-allowed', rootField }
  }
  const rule = ROOT_FIELD_RULES[root.name.value]
  if (rule.operation !== operation.operation) {
    return { reason: 'wrong-operation-type', rootField }
  }
  if (rule.caller !== caller) {
    return { reason: 'wrong-caller', rootField }
  }
  if (
    !root.selectionSet ||
    !isSelectionAllowed(root.selectionSet, rule.selection)
  ) {
    return { reason: 'selection-not-allowed', rootField }
  }

  // Unset variables resolve to undefined here, so a default value declared
  // in the document cannot satisfy these checks.
  const args = Object.create(null)
  for (const arg of root.arguments ?? []) {
    args[arg.name.value] = valueFromASTUntyped(arg.value, variables ?? {})
  }
  if (!hasOnlyKeys(args, rule.argNames) || !rule.allowArgs(args, uid, email)) {
    return { reason: 'arguments-not-allowed', rootField }
  }

  // Forward the printed document, so the backend executes exactly what was
  // checked here even if its parser version differs from this one.
  return {
    forwardBody: JSON.stringify({
      query: print(document),
      variables: variables ?? undefined,
      operationName: operationName || undefined,
    }),
  }
}

function isValidInternalKey(presented, expected) {
  if (!presented || !expected) {
    return false
  }
  const a = crypto.createHash('sha256').update(presented).digest()
  const b = crypto.createHash('sha256').update(expected).digest()
  return crypto.timingSafeEqual(a, b)
}

/**
 * Create the gate placed in front of `/member/graphql`. It must run before
 * the headless session is attached.
 * @param {Object} opts
 * @param {string} opts.jwtSecret
 * @param {string} [opts.internalApiKey]
 * @returns {express.RequestHandler}
 */
export function createMemberGqlGate({ jwtSecret, internalApiKey = '' }) {
  const parseJson = express.json({ limit: '64kb' })
  const verifyToken = verifyAccessToken({ jwtSecret })

  return (req, res, next) => {
    if (req.method !== 'POST') {
      next()
      return
    }

    const reject = (status, reason, rootField) => {
      console.log(
        JSON.stringify({
          severity: 'NOTICE',
          message: 'member gate rejected a request',
          gate: { reason, rootField, status },
          ...res.locals.globalLogFields,
        })
      )
      res.status(status).send({ status: 'fail', data: 'Request not allowed.' })
    }

    const evaluate = (identity) => {
      parseJson(req, res, (err) => {
        if (err) {
          reject(statusCodes.badRequest, 'body-unreadable')
          return
        }
        const result = evaluateMemberRequest(req.body, identity)
        if (result.reason) {
          reject(statusCodes.forbidden, result.reason, result.rootField)
          return
        }
        // @ts-ignore read by `onProxyReq` in the GraphQL proxy mini app
        req.gatedGraphQLBody = result.forwardBody
        next()
      })
    }

    if (req.originalUrl.includes('?')) {
      reject(statusCodes.badRequest, 'query-string-present')
      return
    }

    if (isValidInternalKey(req.header('X-Internal-Api-Key'), internalApiKey)) {
      evaluate({ caller: CALLER.internal })
      return
    }
    if (!req.header('Authorization')) {
      reject(statusCodes.unauthorized, 'anonymous')
      return
    }
    verifyToken(req, res, (err) => {
      if (err) {
        reject(statusCodes.unauthorized, 'invalid-token')
        return
      }
      const sub = res.locals.auth?.decodedAccessToken?.sub
      const uid = typeof sub === 'string' ? sub.split('|')[1] : undefined
      if (!uid) {
        reject(statusCodes.unauthorized, 'token-without-subject')
        return
      }
      evaluate({
        caller: CALLER.user,
        uid,
        email: res.locals.auth?.decodedAccessToken?.email,
      })
    })
  }
}
