import { statusCodes } from './constants'
// @ts-ignore `@twreporter/errors` does not have tyepscript definition file yet
import errors from '@twreporter/errors'
import crypto from 'crypto'
import express from 'express'
import { parse as parseGraphQL } from 'graphql'
import middlewareCreator from './middlewares'
import { createProxyMiddleware, fixRequestBody } from 'http-proxy-middleware'

/**
 *  This function creates a mini app.
 *  This mini app aims to handle requests' authorization and
 *  proxies requests to backed GraphQL API origin server.
 *
 *  @param {Object} opts
 *  @param {string} opts.jwtSecret
 *  @param {string} opts.proxyOrigin
 *  @param {'/content/graphql'|'/member/graphql'} opts.proxyPath
 *  @param {string} [opts.sessionTokenKey]
 *  @returns {express.Router}
 */
/**
 * Decide whether a GraphQL request body contains a mutation operation,
 * using the same grammar the backend executes (graphql-js `parse`), so
 * lexer quirks (ignored commas/BOM, comments, block strings, multiple
 * operations selected via `operationName`) cannot produce a document that
 * reads as a query here but executes as a mutation upstream.
 * Unparseable input is treated as a mutation (fail closed) and left for
 * the backend to reject.
 * @param {unknown} query
 * @returns {boolean}
 */
function isMutation(query) {
  if (typeof query !== 'string') {
    return true
  }
  try {
    const document = parseGraphQL(query, { noLocation: true })
    return document.definitions.some(
      (definition) =>
        definition.kind === 'OperationDefinition' &&
        definition.operation === 'mutation'
    )
  } catch (err) {
    return true
  }
}

/**
 * Constant-time string comparison that never throws on length mismatch.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeEqualStr(a, b) {
  const bufA = Buffer.from(String(a))
  const bufB = Buffer.from(String(b))
  if (bufA.length !== bufB.length) {
    return false
  }
  return crypto.timingSafeEqual(bufA, bufB)
}

export function createGraphQLProxy({
  jwtSecret,
  proxyOrigin,
  proxyPath,
  sessionTokenKey,
  bypassAuthorization = false,
  internalApiKey = '',
}) {
  // create express mini app
  const router = express.Router()

  // enable pre-flight request
  router.options(proxyPath)

  const verifyAccessToken = middlewareCreator.verifyAccessToken({
    jwtSecret,
  })

  router.post(
    proxyPath,

    // Express does not parse request bodies by itself; the mutation gate
    // below needs `req.body.query`. The consumed stream is replayed to the
    // upstream by `fixRequestBody` in `onProxyReq`.
    express.json({ limit: '2mb' }),

    // verify access token if needed
    /** @type {express.RequestHandler} */
    (req, res, next) => {
      // Skip verification when bypass flag is enabled
      if (!bypassAuthorization && req.header('Authorization')) {
        verifyAccessToken(req, res, next)
        return
      }

      // Otherwise, we skip authorization.
      // get to next middleware
      next()
    },

    // Reject writes from the public internet. A GraphQL mutation is allowed
    // only when the caller is either (a) an authenticated user — the previous
    // middleware set res.locals.auth from a valid access token (e.g. a logged-in
    // member on /member/graphql), or (b) an internal writer presenting the
    // shared key. Read-only queries are always allowed. Without this gate the
    // backend CMS (gql strategy) applies no write access control, so anyone
    // could create/update/delete.
    /** @type {express.RequestHandler} */
    (req, res, next) => {
      if (!isMutation(req?.body?.query)) {
        next()
        return
      }
      if (res?.locals?.auth) {
        next()
        return
      }
      const presentedKey = req.header('X-Internal-Api-Key') || ''
      if (
        internalApiKey &&
        presentedKey &&
        timingSafeEqualStr(presentedKey, internalApiKey)
      ) {
        next()
        return
      }
      res.status(statusCodes.unauthorized).send({
        status: 'error',
        error: 'Mutations require authentication or a valid internal API key.',
      })
    },

    // proxy request to API GraphQL endpoint
    createProxyMiddleware({
      target: proxyOrigin,
      changeOrigin: true,
      pathRewrite: {
        [proxyPath]: '/api/graphql',
      },
      // add `X-Access-Token-Scope` custom header.
      // The api servers use this custom header to implement access control mechanism.
      onProxyReq: (proxyReq, req, res) => {
        // @ts-ignore `res.locals` is not defined in 'http-proxy-middleware' pkg,
        // but it does exist in 'express' res object.
        let scope = res?.locals?.auth?.decodedAccessToken?.scope || ''

        // When bypass is enabled, grant full content scope to all requests
        if (bypassAuthorization) {
          scope = 'read:posts read:member-posts:all'
        }

        proxyReq.setHeader('X-Access-Token-Scope', scope)

        if (sessionTokenKey) {
          const sessionToken = res.locals[sessionTokenKey]
          // remove Authorization header to prevent authenication fail on gql side
          proxyReq.removeHeader('Authorization')
          proxyReq.setHeader('Cookie', `keystonejs-session=${sessionToken}`)
        }

        console.log(
          JSON.stringify({
            severity: 'DEBUG',
            message:
              'proxy to backed API origin server: ' +
              proxyOrigin +
              proxyReq.path,
            ...res?.locals?.globalLogFields,
          })
        )

        // express.json() consumed the request stream: re-send the parsed
        // body. Must run after every setHeader above — it writes the body,
        // which flushes the headers.
        fixRequestBody(proxyReq, req)
      },
      onError: (
        err,
        req,
        res,
        /* eslint-disable-line no-unused-vars */ target
      ) => {
        const annotatingError = errors.helpers.wrap(
          err,
          'ProxyError',
          `Error occurs while proxying request to API origin server: ${proxyOrigin}` +
            err.message
        )

        console.log(
          JSON.stringify({
            severity: 'ERROR',
            message: errors.helpers.printAll(annotatingError, {
              withStack: true,
              withPayload: true,
            }),
            ...res?.locals?.globalLogFields,
          })
        )

        res.status(statusCodes.internalServerError).send({
          status: 'error',
          error: annotatingError.message,
        })
      },
    })
  )

  router.use(
    /**
     * Mini app level error handler
     * @type {express.ErrorRequestHandler}
     */
    (err, req, res, next) => {
      switch (err.name) {
        case 'AuthError': {
          console.log(
            JSON.stringify({
              severity: 'NOTICE',
              message: 'Authorization token is invalid.' + err.message,
              ...res.locals.globalLogFields,
            })
          )
          res.status(statusCodes.unauthorized).send({
            status: 'fail',
            data: err.message + ' Authorization token is invalid.',
          })
          return
        }
        default: {
          // Let application level error handle to deal with the error
          next(err)
          return
        }
      }
    }
  )

  return router
}
