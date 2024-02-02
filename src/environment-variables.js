const {
  JWT_SECRET,
  JWT_LIFE_TIME, // seconds
  GCP_PROJECT_ID,
  FIREBASE_PROJECT_ID,
  ISRAFEL_GQL_ORIGIN,
  WEEKLY_GQL_ORIGIN,
  CORS_ALLOW_ORIGINS,
  GCS_ORIGIN,
  YOUTUBE_ORIGIN,
  SECRET_RESOURCE_ID,
  RELEASE_BRANCH,
} = process.env

/**
 *
 * @param {string} [cors]
 * @returns {'*' | string[]}
 */
const getAllowOrigins = (cors) => {
  if (cors === '*') {
    return '*'
  } else if (typeof cors === 'string') {
    return cors.split(',')
  } else {
    return ['https://www.mirrormedia.mg', 'https://mirrormedia.mg']
  }
}

const jwtLifeTime = Number(JWT_LIFE_TIME)

const envVar = {
  jwt: {
    secret: JWT_SECRET || 'jwt-secret',
    lifetime: Number.isNaN(jwtLifeTime) ? 3600 : jwtLifeTime,
  },
  gcp: {
    projectId: GCP_PROJECT_ID || 'mirrormedia-1470651750304',
  },
  firebase: {
    projectId: FIREBASE_PROJECT_ID || 'mirror-weekly',
  },
  apis: {
    israfel: {
      origin: ISRAFEL_GQL_ORIGIN || 'https://dev-israfel-gql.mirrormedia.mg',
    },
    weekly: {
      origin:
        WEEKLY_GQL_ORIGIN || 'https://mirror-cms-dev-ufaummkd5q-de.a.run.app',
    },
  },
  cors: {
    allowOrigins: getAllowOrigins(CORS_ALLOW_ORIGINS),
  },
  gcs: {
    origin: GCS_ORIGIN || 'https://v3-statics.mirrormedia.mg',
  },
  youtube: {
    origin: YOUTUBE_ORIGIN || 'https://api.mirrormedia.mg',
  },
  secretResourceId:
    SECRET_RESOURCE_ID ||
    'projects/983956931553/secrets/dev-weekly-api-server/versions/1',
  releaseBranch: RELEASE_BRANCH || 'prod',
}

export default envVar
