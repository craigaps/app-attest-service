# 🛡️ App Attest Service

This Node.js service provides secure HTTPS endpoints for Apple App Attestation workflows. It uses Express and requires SSL certificates and environment configuration to run properly.

---

## 🔐 Environment Configuration

Create a `.env` file in the root of the project with the following entries:

```env
APPLE_APP_ATTEST_ENVIRONENT=development                         # Set to 'development' or 'production'
APPLE_APP_ATTEST_CERTIFICATE=Apple_App_Attestation_Root_CA.pem  # Filename of Apple App Attestation Root CA certificate
HTTPS_PRIVATE_KEY=https_key.pem                                 # Filename of HTTPS server private key
HTTPS_CERTIFICATE=https_cert.pem                                # Filename of HTTPS server certificate
```

## 🚀 Run the service

To start the service, in the root directory run `npm start`.
