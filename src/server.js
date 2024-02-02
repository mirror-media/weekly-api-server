import http from 'http'
import { createApp } from './app'
import envVar from './environment-variables'
import secretManager from './secret-manager'

const port = process.env.PORT || '8080'

/**
 * @typedef {Object} Account
 * @property {string} email
 * @property {string} password
 *
 * @typedef {Object} Secret
 * @property {Account} israfelHeadlessAccount
 * @property {Account} contentGQLHeadlessAccount
 */

async function start() {
  let israfelHeadlessAccount
  let contentGQLHeadlessAccount
  try {
    /** @type {Secret} */
    let jsonObj
    if (envVar.releaseBranch === 'local') {
      jsonObj = {
        israfelHeadlessAccount: {
          email: 'weekly-api-server@mirrormedia.mg',
          password: 'get_password_from_israfel_cms',
        },
        contentGQLHeadlessAccount: {
          email: 'weekly-api-server@mirrormedia.mg',
          password: 'get_password_from_content_cms',
        },
      }
    } else {
      const value = await secretManager.getSecretValue(envVar.secretResourceId)
      jsonObj = JSON.parse(value)
    }
    israfelHeadlessAccount = jsonObj.israfelHeadlessAccount
    contentGQLHeadlessAccount = jsonObj.contentGQLHeadlessAccount
  } catch (err) {
    console.error(
      JSON.stringify({
        severity: 'ALERT',
        // All exceptions that include a stack trace will be
        // integrated with Error Reporting.
        // See https://cloud.google.com/run/docs/error-reporting
        message: err.stack
          ? `Error to get secrets: ${err.stack}`
          : new Error('Error to get secrets').stack,
      })
    )
    return
  }

  let server
  try {
    const app = createApp({
      gcpProjectId: envVar.gcp.projectId,
      firebaseProjectId: envVar.firebase.projectId,
      jwtSecret: envVar.jwt.secret,
      jwtLifeTime: envVar.jwt.lifetime,
      israfelProxyOrigin: envVar.apis.israfel.origin,
      weeklyProxyOrigin: envVar.apis.weekly.origin,
      gcsProxyOrigin: envVar.gcs.origin,
      corsAllowOrigin: envVar.cors.allowOrigins,
      youtubeProxyOrigin: envVar.youtube.origin,
      israfelHeadlessAccount,
      contentGQLHeadlessAccount,
    })
    server = http.createServer(app).listen(port, () => {
      console.log(
        JSON.stringify({
          severity: 'NOTICE',
          message: `server starts at port ${port}`,
        })
      )
    })
  } catch (err) {
    console.error(
      JSON.stringify({
        severity: 'ALERT',
        // All exceptions that include a stack trace will be
        // integrated with Error Reporting.
        // See https://cloud.google.com/run/docs/error-reporting
        message: err.stack
          ? `Error to start server: ${err.stack}`
          : new Error('Error to start server').stack,
      })
    )
  }

  process.on('SIGTERM', () => {
    console.log('SIGTERM signal received')
    if (server) {
      console.log('Close HTTP server')
      server.close(() => {
        console.log('HTTP server closed')
      })
    }
  })

  process.on('SIGINT', () => {
    console.log('SIGINT signal received')
    if (server) {
      console.log('Close HTTP server')
      server.close(() => {
        console.log('HTTP server closed')
      })
    }
  })
}

start()
