import express from 'express' // eslint-disable-line
// @ts-ignore `@twreporter/errors` does not provide typescript definition file.
import errors from '@twreporter/errors'
import jwt from 'jsonwebtoken'
import { initializeApp, App } from 'firebase-admin/app' // eslint-disable-line
import { getAuth, DecodedIdToken } from 'firebase-admin/auth' // eslint-disable-line

/** @type {App} */
let firebaseApp

/**
 *  This function creates an Express middleware.
 *  The created middleware could be used to validate the request authentication
 *  by firebase admin SDK.
 *
 *  The middleware also set decoded token object into `res.locals.auth.decodedIdToken`.
 *
 *  @param {Object} [opts={}]
 *  @param {string} [opts.firebaseProjectId]
 *  @returns {express.RequestHandler} express middleware
 */
export function verifyIdTokenByFirebaseAdmin(opts = {}) {
  return async (req, res, next) => {
    if (!firebaseApp) {
      firebaseApp = initializeApp({
        projectId: opts.firebaseProjectId,
      })
    }
    try {
      // Get the JWT in the "Authorization" header.
      const bearer = req.header('Authorization') || ''
      const [, token] = bearer.match(/Bearer (.*)/) || []

      if (!token) {
        throw new Error('Bearer token is empty')
      }

      // Verify and decode the JWT.
      const decodedIdToken = await getAuth(firebaseApp).verifyIdToken(token)

      // set `res.locals.auth.decodedIdToken` for next middlewares
      res.locals.auth = {
        decodedIdToken,
      }
    } catch (err) {
      const annotatingError = errors.helpers.wrap(
        err,
        'AuthError',
        'Authentication fails in `verifyIdTokenByFirebaseAdmin` middleware: ' +
          err.message
      )
      next(annotatingError)
      return
    }

    next()
  }
}

/**
 *  This function creates an Express middleware.
 *  The created middleware could verify the request authorization.
 *
 *  The middleware also set decoded token object into `res.locals.auth.decodedAccessToken`.
 *
 *  @param {Object} [opts={}]
 *  @param {string} [opts.jwtSecret='']
 *  @returns {express.RequestHandler} express middleware
 */
export function verifyAccessToken(opts = {}) {
  const jwtSecret = opts.jwtSecret || ''

  if (!jwtSecret) {
    console.log(
      JSON.stringify({
        severity: 'ERROR',
        message: new Error('JWT secert is not a valid string').stack,
      })
    )

    // TODO: throw Error to stop server
  }

  return (req, res, next) => {
    try {
      // Get the JWT in the "Authorization" header.
      const bearer = req.header('Authorization') || ''
      const [, token] = bearer.match(/Bearer (.*)/) || []

      if (!token) {
        throw new Error('Bearer token is empty')
      }

      const decoded = jwt.verify(token, jwtSecret)

      // set `res.locals.auth.decodedAccessToken` for next middlewares
      res.locals.auth = {
        decodedAccessToken: decoded,
      }
    } catch (err) {
      const annotatingError = errors.helpers.wrap(
        err,
        'AuthError',
        'Authentication fails in `verifyAccessToken` middleware: ' + err.message
      )
      next(annotatingError)
      return
    }

    next()
  }
}

/**
 *  This function creates an Express middleware.
 *  The created middleware could sign the JWT access token.
 *
 *  @param {Object} opts
 *  @param {string} opts.jwtSecret
 *  @param {number} opts.jwtLifeTime
 *  @returns {express.RequestHandler}
 */
export function signAccessToken({ jwtSecret, jwtLifeTime }) {
  return (req, res, next) => {
    const nowTs = Math.round(new Date().getTime() / 1000) // timestamp
    const expiresIn = nowTs + jwtLifeTime
    const {
      id: memberId, // eslint-disable-line no-unused-vars
      type: memberType,
      subscription: subscriptions,
    } = res.locals.memberInfo || {}
    const firebaseId =
      res.locals.memberInfo?.firebaseId || res.locals.auth?.decodedIdToken?.uid
    let roles = ['']
    let scope = ''

    switch (memberType) {
      case 'marketing':
      case 'subscribe_group':
      case 'subscribe_yearly':
      case 'subscribe_monthly': {
        roles = ['premium-member']
        scope = `read:posts read:member-posts:all read:member-info:${firebaseId} write:member-info:${firebaseId}`
        break
      }
      case 'subscribe_one_time': {
        roles = ['one-time-member']
        scope = `read:posts read:member-info:${firebaseId} write:member-info:${firebaseId}`
        if (Array.isArray(subscriptions)) {
          const postIdArr = subscriptions
            .filter((s) => s?.postId)
            .map((s) => s.postId)
          scope += `read:member-posts:${postIdArr.join(',')}`
        }
        break
      }
      case 'none':
      default: {
        roles = ['basic-member']
        scope = `read:posts read:member-info:${firebaseId} write:member-info:${firebaseId}`
        break
      }
    }

    const jwtPayload = {
      // TODO: add domain name mapping
      // and return different hostname according to different environment
      iss: 'https://api-v2.mirrormedia.mg',
      sub: `mirror-weekly|${firebaseId}`,
      aud: [
        // TODO: return one of the following according to different environment
        'https://www.mirrormedia.mg',
        'https://www-staging.mirrormedia.mg',
        'https://dev.mirrormedia.mg',
        'http://localhost:3000',
      ],
      exp: expiresIn,
      iat: nowTs,
      roles,
      scope,
    }

    let token
    try {
      token = jwt.sign(jwtPayload, jwtSecret)
    } catch (err) {
      const annotatingError = errors.helpers.wrap(
        err,
        'SignJWTError',
        'Error to sign JWT access token'
      )
      next(annotatingError)
      return
    }

    res.locals.accessTokenPayload = {
      access_token: token,
      token_type: 'Bearer',
      expires_in: expiresIn,
    }

    next()
  }
}

/**
 * verify whether the user is internal colleague with decodeIdToken
 *
 * @param {DecodedIdToken} [decodedIdToken]
 * @returns {boolean}
 */
function isInternalColleage(decodedIdToken = {}) {
  let pass = false

  const domainList = [
    '@mirrormedia.mg',
    '@mnews.com.tw',
    '@mnews.tw',
    '@mirrorfiction.com',
  ]

  const email = decodedIdToken.email
  const signInProvider = decodedIdToken.firebase?.sign_in_provider

  if (typeof email === 'string' && signInProvider === 'google.com') {
    pass = domainList.reduce((prev, domain) => {
      return (prev = prev || email.endsWith(domain))
    }, pass)
  }

  return pass
}

/**
 *  This function creates an Express middleware.
 *  The created middleware could sign the JWT access token
 *  to our internal colleagues.
 *
 *  @param {Object} opts
 *  @param {string} opts.jwtSecret
 *  @param {number} opts.jwtLifeTime
 *  @returns {express.RequestHandler}
 */
export function signAccessTokenForInternalColleague({
  jwtSecret,
  jwtLifeTime,
}) {
  return (req, res, next) => {
    const nowTs = Math.round(new Date().getTime() / 1000) // timestamp
    const expiresIn = nowTs + jwtLifeTime
    const firebaseId = res.locals.auth?.decodedIdToken?.uid

    // skip this middleware if not internal colleague
    if (!isInternalColleage(res.locals.auth?.decodedIdToken)) {
      return next()
    }

    // grant whole posts access permission
    const scope = `read:posts read:member-posts:all read:member-info:${firebaseId} write:member-info:${firebaseId}`

    const jwtPayload = {
      // TODO: add domain name mapping
      // and return different hostname according to different environment
      iss: 'https://api-v2.mirrormedia.mg',
      sub: `mirror-weekly|${firebaseId}`,
      aud: [
        // TODO: return one of the following according to different environment
        'https://www.mirrormedia.mg',
        'https://www-staging.mirrormedia.mg',
        'https://dev.mirrormedia.mg',
        'http://localhost:3000',
      ],
      exp: expiresIn,
      iat: nowTs,
      roles: ['staff'],
      scope,
    }

    let token
    try {
      token = jwt.sign(jwtPayload, jwtSecret)
    } catch (err) {
      const annotatingError = errors.helpers.wrap(
        err,
        'SignJWTError',
        'Error to sign JWT access token'
      )
      next(annotatingError)
      return
    }

    res.locals.accessTokenPayload = {
      access_token: token,
      token_type: 'Bearer',
      expires_in: expiresIn,
    }

    next()
  }
}
