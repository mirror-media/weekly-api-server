import { createLoggerMw } from './logger'
import { createMemberGqlGate } from './member-gql-gate'
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
  createMemberGqlGate,
  queryMemberInfo,
  verifyAccessToken,
  verifyIdTokenByFirebaseAdmin,
  signAccessToken,
  signAccessTokenForInternalColleague,
}

export default mws
