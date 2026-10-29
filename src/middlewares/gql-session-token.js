import axios from 'axios'
import errors from '@twreporter/errors'
import express from 'express' // eslint-disable-line
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import { sessionTokenKey } from '../constants'

/**
 * Soft-verify an access token from the Authorization header.
 * Returns true only for a present, valid Bearer JWT. Never throws.
 * @param {import('express').Request} req
 * @param {string} jwtSecret
 * @returns {boolean}
 */
function hasValidAccessToken(req, jwtSecret) {
  try {
    const bearer = req.header('Authorization') || ''
    const [, token] = bearer.match(/Bearer (.*)/) || []
    if (!token || !jwtSecret) {
      return false
    }
    jwt.verify(token, jwtSecret)
    return true
  } catch (err) {
    return false
  }
}

/**
 * Constant-time check of the shared internal key header.
 * @param {import('express').Request} req
 * @param {string} internalApiKey
 * @returns {boolean}
 */
function hasValidInternalKey(req, internalApiKey) {
  const presented = req.header('X-Internal-Api-Key') || ''
  if (!internalApiKey || !presented) {
    return false
  }
  const bufA = Buffer.from(presented)
  const bufB = Buffer.from(internalApiKey)
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB)
}

class IsrafelSessionTokenManager {
  /** @type {IsrafelSessionTokenManager} */
  static instance = null

  /**
   * @constructor
   */
  constructor(apiUrl = 'http://localhost:3000/api/graphql') {
    /** @type {string} */
    this.apiUrl = apiUrl
    /** @type {string} */
    this.sessionToken = ''
    /** @type {number} */
    this.sessionTokenIssueTimestamp = -1
  }

  // Sigleton
  static getInstance(apiUrl) {
    if (IsrafelSessionTokenManager.instance === null) {
      IsrafelSessionTokenManager.instance = new IsrafelSessionTokenManager(
        apiUrl
      )
    }
    return IsrafelSessionTokenManager.instance
  }

  /**
   *  @param {string} email
   *  @param {string} password
   *  @param {number} maxStale - Return stale session token if token's age is less than `maxStale` .unit is second.
   *  @return {Promise<string>} - session token
   */
  async getSessionToken(email, password, maxStale = 3600) {
    const now = Math.round(Date.now() / 1000)
    if (
      this.sessionToken &&
      now - this.sessionTokenIssueTimestamp <= maxStale
    ) {
      return this.sessionToken
    }

    const apiUrl = this.apiUrl
    const query = `
mutation {
  authenticateuserWithPassword(email: "${email}", password: "${password}") {
      ... on userAuthenticationWithPasswordSuccess {
        sessionToken
      }

      ... on userAuthenticationWithPasswordFailure {
        code
        message
      }
  }
}
    `

    try {
      const apiRes = await axios.post(apiUrl, {
        query,
      })

      const { data, errors: gqlErrors } = apiRes.data

      if (gqlErrors) {
        const annotatingError = errors.helpers.wrap(
          new Error('Errors occured while requesting Israfel GQL.'),
          'GraphQLError',
          'Errors returned in `authenticateuserWithPassword` mutation',
          {
            gqlErrors,
          }
        )
        throw annotatingError
      }
      const { sessionToken, code, message } = data.authenticateuserWithPassword

      if (code) {
        const annotatingError = errors.helpers.wrap(
          new Error('Fail to pass Israfel authentication layer.'),
          'AuthenticationFailure',
          `Failure code: ${code}, message: ${message}`
        )
        throw annotatingError
      }

      if (sessionToken) {
        this.sessionToken = sessionToken
        this.sessionTokenIssueTimestamp = Math.round(Date.now() / 1000)
      }
      return this.sessionToken
    } catch (axiosErr) {
      throw errors.helpers.wrap(
        errors.helpers.annotateAxiosError(axiosErr),
        'IsrafelSessionTokenManagerError',
        'Can not get access token successfully.'
      )
    }
  }
}

/**
 *  Create an express middleware to get session token from Israfel
 *  and set the token to `res.locals.israfelSessionToken`.
 *  @param {Object} opts
 *  @param {string} opts.apiUrl
 *  @param {Object} opts.headlessAccount
 *  @param {string} opts.headlessAccount.email
 *  @param {string} opts.headlessAccount.password
 *  @return {express.RequestHandler} express middleware
 */
export function createIsrafelSessionTokenMw({
  apiUrl,
  headlessAccount: { email, password },
  jwtSecret = '',
  internalApiKey = '',
  onlyWhenAuthenticated = false,
}) {
  const tokenManager = IsrafelSessionTokenManager.getInstance(apiUrl)
  return async (req, res, next) => {
    try {
      // When guarding the public member proxy, only attach the internal
      // headless-account session for requests that carry a valid access
      // token or the shared internal key (trusted server-side callers such
      // as the papermag order flow). Anonymous requests are forwarded
      // without it, so Israfel's own access control — not our privileged
      // account — decides what they may read.
      if (
        onlyWhenAuthenticated &&
        !hasValidAccessToken(req, jwtSecret) &&
        !hasValidInternalKey(req, internalApiKey)
      ) {
        next()
        return
      }
      const key = sessionTokenKey.member
      const sessionToken = await tokenManager.getSessionToken(email, password)
      res.locals[key] = sessionToken
    } catch (err) {
      const annotatingError = errors.helpers.wrap(
        err,
        'IsrafelSessionTokenMwError',
        `Error to get session token from GQL.`
      )
      next(annotatingError)
    }

    next()
  }
}

class ContentGQLSessionTokenManager {
  /** @type {ContentGQLSessionTokenManager} */
  static instance = null

  /**
   * @constructor
   */
  constructor(apiUrl = 'http://localhost:3000/api/graphql') {
    /** @type {string} */
    this.apiUrl = apiUrl
    /** @type {string} */
    this.sessionToken = ''
    /** @type {number} */
    this.sessionTokenIssueTimestamp = -1
  }

  // Sigleton
  static getInstance(apiUrl) {
    if (ContentGQLSessionTokenManager.instance === null) {
      ContentGQLSessionTokenManager.instance =
        new ContentGQLSessionTokenManager(apiUrl)
    }
    return ContentGQLSessionTokenManager.instance
  }

  /**
   *  @param {string} email
   *  @param {string} password
   *  @param {number} maxStale - Return stale session token if token's age is less than `maxStale` .unit is second.
   *  @return {Promise<string>} - session token
   */
  async getSessionToken(email, password, maxStale = 3600) {
    const now = Math.round(Date.now() / 1000)
    if (
      this.sessionToken &&
      now - this.sessionTokenIssueTimestamp <= maxStale
    ) {
      return this.sessionToken
    }

    const apiUrl = this.apiUrl
    const query = `
mutation {
  authenticateUserWithPassword(email: "${email}", password: "${password}") {
      ... on UserAuthenticationWithPasswordSuccess {
        sessionToken
      }

      ... on UserAuthenticationWithPasswordFailure {
        message
      }
  }
}
    `

    try {
      const apiRes = await axios.post(apiUrl, {
        query,
      })

      const { data, errors: gqlErrors } = apiRes.data

      if (gqlErrors) {
        const annotatingError = errors.helpers.wrap(
          new Error('Errors occured while requesting Content GQL.'),
          'GraphQLError',
          'Errors returned in `authenticateUserWithPassword` mutation',
          {
            gqlErrors,
          }
        )
        throw annotatingError
      }

      const { sessionToken, message } = data.authenticateUserWithPassword

      if (message) {
        const annotatingError = errors.helpers.wrap(
          new Error('Fail to pass Content GQL authentication layer.'),
          'AuthenticationFailure',
          `Failure message: ${message}`
        )
        throw annotatingError
      }

      if (sessionToken) {
        this.sessionToken = sessionToken
        this.sessionTokenIssueTimestamp = Math.round(Date.now() / 1000)
      }
      return this.sessionToken
    } catch (axiosErr) {
      throw errors.helpers.wrap(
        errors.helpers.annotateAxiosError(axiosErr),
        'ContentGQLSessionTokenManagerError',
        'Can not get access token successfully.'
      )
    }
  }
}

/**
 *  Create an express middleware to get session token from Content GQL
 *  and set the token to `res.locals.contentGQLSessionToken`.
 *  @param {Object} opts
 *  @param {string} opts.apiUrl
 *  @param {Object} opts.headlessAccount
 *  @param {string} opts.headlessAccount.email
 *  @param {string} opts.headlessAccount.password
 *  @return {express.RequestHandler} express middleware
 */
export function createContentGQLSessionTokenMw({
  apiUrl,
  headlessAccount: { email, password },
}) {
  const tokenManager = ContentGQLSessionTokenManager.getInstance(apiUrl)
  return async (req, res, next) => {
    try {
      const key = sessionTokenKey.member
      const sessionToken = await tokenManager.getSessionToken(email, password)
      res.locals[key] = sessionToken
    } catch (err) {
      const annotatingError = errors.helpers.wrap(
        err,
        'ContentGQLSessionTokenMwError',
        `Error to get session token from GQL.`
      )
      next(annotatingError)
    }

    next()
  }
}
