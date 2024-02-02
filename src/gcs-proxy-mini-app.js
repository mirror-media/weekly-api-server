import express from 'express'
import { createProxyMiddleware } from 'http-proxy-middleware'

/**
 *  This function creates a mini app.
 *  This mini app aims to proxy requests to Google Cloud Storage.
 *
 *  @param {Object} opts
 *  @param {string} opts.proxyOrigin
 *  @returns {express.Router}
 */
export function createGcsProxy({ proxyOrigin }) {
  // create express mini app
  const router = express.Router()

  router.use(
    '/gcs',
    // proxy request to API GraphQL endpoint
    createProxyMiddleware({
      target: proxyOrigin,
      changeOrigin: true,
      pathRewrite: (path) => path.replace(/^\/gcs/, ''),
      // eslint-disable-next-line no-unused-vars
      onProxyReq: (proxyReq, req, res) => {
        proxyReq.setHeader('X-PROXIED-BY', 'Weekly API Server')
      },
    })
  )

  return router
}
