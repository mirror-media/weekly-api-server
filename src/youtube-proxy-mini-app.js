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
export function createYoutubeProxy({ proxyOrigin }) {
  // create express mini app
  const router = express.Router()

  console.log('proxyOrigin:', proxyOrigin)
  router.use(
    '/youtube',
    // proxy request to API GraphQL endpoint
    createProxyMiddleware({
      target: proxyOrigin,
      changeOrigin: true,
      // eslint-disable-next-line no-unused-vars
      onProxyReq: (proxyReq, req, res) => {
        proxyReq.setHeader('X-PROXIED-BY', 'Weekly API Server')
      },
    })
  )

  return router
}
