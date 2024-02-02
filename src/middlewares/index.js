import { createLoggerMw } from './logger'
import { queryMemberInfo } from './member-info'
import {
  verifyAccessToken,
  verifyIdTokenByFirebaseAdmin,
  signAccessToken,
  signAccessTokenForInternalColleague,
} from './auth'
import {
  createContentGQLSessionTokenMw,
  createIsrafelSessionTokenMw,
} from './gql-session-token'

const mws = {
  createLoggerMw,
  createContentGQLSessionTokenMw,
  createIsrafelSessionTokenMw,
  queryMemberInfo,
  verifyAccessToken,
  verifyIdTokenByFirebaseAdmin,
  signAccessToken,
  signAccessTokenForInternalColleague,
}

export default mws
