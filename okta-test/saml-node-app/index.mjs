import express from 'express'
import axios from 'axios'
import {makeIdpConfig, makeSPConfig, SamlServiceProvider} from '@brightmls/auth'
const app = express()
const port = 3000

// Utility functions to fetch IDP metadata and build SP metadata
const getIdpMetadata = async (metadataUrl) => {
  const response = await axios.get(metadataUrl)
  return response.data
} 

const getSPMetadata = (entityId, acsURL) => {
  return `<?xml version="1.0"?>
  <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}">
      <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          <md:KeyDescriptor use="signing">
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data>
              <ds:X509Certificate>${process.env.ENCRYPT_PUBLIC_CERT}</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:KeyDescriptor use="encryption">
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data>
              <ds:X509Certificate>${process.env.ENCRYPT_PUBLIC_CERT}</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
          <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
          <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${acsURL}" isDefault="true" index="0" />        
      </md:SPSSODescriptor>
  </md:EntityDescriptor>`
}

// SAML setup
const idpMeta = await getIdpMetadata(process.env.IDP_METADATA_URL)
const spMeta = getSPMetadata(process.env.SP_ENTITY_ID, process.env.SP_ACS_URL)
const idp = makeIdpConfig(idpMeta)
const sp = makeSPConfig(spMeta, process.env.ENCRYPT_PRIVATE_KEY, undefined, process.env.ENCRYPT_PRIVATE_KEY)
const saml = new SamlServiceProvider(idp, sp)

app.use(express.urlencoded({extended: true}));
app.use(express.json()) 

app.get("/login", async (req, res) => {
  const { context } = saml.createLoginRequest("redirect");
  return res.redirect(context);
});

app.post('/auth/saml', async (req, res) => {
    // parse the IDP Login Response
    const {SAMLResponse} = req.body
    const attributes = await saml.parseResponse({ body: { SAMLResponse } })

    res.send(`<!doctype html>
      <html>
          <title>SAML Response Handler</title>
          <body>
              <h2>SAML Assertion</h2>
              
              ${JSON.stringify(attributes)}
              ${JSON.stringify(req.body)}
          </body>
      </html>`)
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})