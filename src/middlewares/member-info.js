import axios from 'axios'
import errors from '@twreporter/errors'
import express from 'express' // eslint-disable-line

/**
 *  This function creates an Express middleware.
 *  The created middleware could be used to validate the request authentication
 *  by firebase admin SDK.
 *
 *  The middleware also set decoded token object into `res.locals.auth.decodedIdToken`.
 *
 *  @param {Object} opts
 *  @param {string} opts.apiUrl
 *  @param {string} opts.sessionTokenKey
 *  @returns {express.RequestHandler} express middleware
 */
export function queryMemberInfo(opts) {
  return async (req, res, next) => {
    const sessionToken = res.locals[opts.sessionTokenKey]
    const firebaseId = res.locals.auth?.decodedIdToken?.uid

    const query = `
  query {
    members(where: { firebaseId: { equals: "${firebaseId}" }}) {
      id
      firebaseId
      type
      email
      subscription(where: { isActive: { equals: true }}){
        postId
      }
    }
  }
`

    let apiRes
    try {
      apiRes = await axios.post(
        opts.apiUrl,
        {
          query,
        },
        {
          headers: {
            'X-Access-Token-Scope': `read:member-info:${firebaseId}`,
            Cookie: `keystonejs-session=${sessionToken}`,
          },
        }
      )
    } catch (axiosErr) {
      const annotatingError = errors.helpers.wrap(
        errors.helpers.annotateAxiosError(axiosErr),
        'MemberInfoError',
        'Error to request GQL server'
      )
      next(annotatingError)
      return
    }

    const { data, errors: gqlErrors } = apiRes.data

    if (gqlErrors) {
      const annotatingError = errors.helpers.wrap(
        new Error('Errors occured while fetching member info.'),
        'MemberInfoError',
        'GQLError: Errors returned in `member` query',
        { gqlErrors }
      )
      next(annotatingError)
      return
    }

    // set `res.locals.auth.memberInfo` for next middlewares
    res.locals.memberInfo = data?.members?.[0]

    next()
  }
}
