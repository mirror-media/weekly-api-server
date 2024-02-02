import { SecretManagerServiceClient } from '@google-cloud/secret-manager'
const secretClient = new SecretManagerServiceClient()

/**
 *  Get secret value from GCP secret manager.
 *  @param {string} resourceID - resource ID provided by GCP secret manager
 *  @return {Promise} Promise.resolve with secret value or Promise.reject with error
 *
 */
async function getSecretValue(resourceID) {
  const [secrect] = await secretClient.accessSecretVersion({
    name: resourceID,
  })

  return secrect.payload.data.toString()
}

export default {
  getSecretValue,
}
