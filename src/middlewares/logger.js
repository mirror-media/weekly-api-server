import express from 'express' // eslint-disable-line

/**
 *  Follow [Writing structured logs](https://cloud.google.com/run/docs/logging#writing_structured_logs)
 *  doc to do logging.
 *
 *  @param {Object} req
 *  @param {Function} req.header
 *  @param {string} projectId
 *  @returns {Object} globalLogFields
 */
function getGlobalLogFields(req, projectId) {
  const globalLogFields = {}

  // Add log correlation to nest all log messages beneath request log in Log Viewer.
  const traceHeader = req.header('X-Cloud-Trace-Context')
  if (traceHeader && projectId) {
    const [trace] = traceHeader.split('/')
    globalLogFields[
      'logging.googleapis.com/trace'
    ] = `projects/${projectId}/traces/${trace}`
  }
  return globalLogFields
}

/**
 *  Create an express middleware to log request.
 *  @param {string} projectId
 *  @returns {express.RequestHandler} express middleware
 */
export function createLoggerMw(projectId) {
  return (req, res, next) => {
    const globalLogFields = getGlobalLogFields(req, projectId)

    console.log(
      JSON.stringify({
        severity: 'INFO',
        message: `Request: ${req.method} ${req.originalUrl}`,
        debugPayload: {
          'req.headers': {
            'Content-Length': req.get('Content-Length'),
            'Content-Type': req.get('Content-Type'),
            Authorization: req.get('Authorization'),
          },
          'req.body': req.body,
        },
        ...globalLogFields,
      })
    )

    res.locals.globalLogFields = globalLogFields

    next()
  }
}
