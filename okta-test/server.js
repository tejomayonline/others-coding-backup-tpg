const express = require("express");
const fs = require("fs");
const saml = require("samlify");
const validator = require("@authenio/samlify-xsd-schema-validator");
const axios = require("axios");
const serveStatic = require("serve-static");
const bodyParser = require("body-parser");
const path = require("path");
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(serveStatic(path.resolve(__dirname, "public")));

saml.setSchemaValidator(validator);

var PORT = 3000;

app.listen(PORT, function (err) {
  if (err) console.log("Error in server setup");
  console.log("Server listening on Port", PORT);
});
// URL to the okta metadata
const uri_okta_metadata =
  "https://okta.dev.brightmls.com/app/exkaev7q5dWUMV63L4x7/sso/saml/metadata";

axios.get(uri_okta_metadata).then((response) => {
  const idp = saml.IdentityProvider({
    metadata: response.data,
    // isAssertionEncrypted: true,
    messageSigningOrder: "encrypt-then-sign",
    // wantLogoutRequestSigned: true,
  });

  const sp = saml.ServiceProvider({
    entityID: "http://127.0.0.1:3000/auth/metadata",
    authnRequestsSigned: false,
    // wantAssertionsSigned: true,
    // wantMessageSigned: true,
    // wantLogoutResponseSigned: true,
    // wantLogoutRequestSigned: true,
    // // the private key (.pem) use to sign the assertion;
    // privateKey: fs.readFileSync(__dirname + "/ssl/jeff/encryptKey.pem"),
    // // the private key pass;
    // privateKeyPass: "12345",
    // // the private key (.pem) use to encrypt the assertion;
    // encPrivateKey: fs.readFileSync(__dirname + "/ssl/encrypt/privkey.pem"),
    // isAssertionEncrypted: false,
    assertionConsumerService: [
      {
        Binding: saml.Constants.namespace.binding.post,
        Location: "http://localhost:3000/auth/saml",
      },
    ],
  });

  app.post("/auth/saml", async (req, res) => {
    try {
      // console.log(req, res);
      const response = await sp.parseLoginResponse(idp, "post", req);

      console.log(response);
      // console.log(response);
      /**
       *
       * Implement your logic here.
       * extract.attributes, should contains : firstName, lastName, email, uid, groups
       *
       **/
    } catch (e) {
      console.error("[FATAL] when parsing login response sent from okta", e);
      return res.redirect("/");
    }
  });

  app.get("/login", async (req, res) => {
    const { id, context } = await sp.createLoginRequest(idp, "redirect");
    console.log({ context });
    return res.redirect(context);
  });

  app.get("/sp/metadata", (req, res) => {
    console.log("here");
    res.header("Content-Type", "text/xml").send(idp.getMetadata());
  });
});
