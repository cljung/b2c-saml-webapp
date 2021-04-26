# B2C Custom Policies for SAML

This is a B2C Custom Policy to support signin using the SAML protocol. 
The policies assumes the following that you already have configured and deployed the TrustFrameworkBase.xml and TrustFrameworkExtensions.xml file in the [SocialAndLocalAccounts starter pack](https://docs.microsoft.com/en-us/azure/active-directory-b2c/saml-service-provider?tabs=windows&pivots=b2c-custom-policy).
The file `TrustFrameworkExtensionsSAML.xml` in this repository inherits from the starter pack file. In file `SignUpOrSigninSAML.xml`, it overrides OrchestrationStep number 7 to issue a SAML assertion instead of a JWT token. If you use another version of the starter pack, you need to adjust the step number so that it matches the last step.

## Documentation
https://docs.microsoft.com/en-us/azure/active-directory-b2c/saml-service-provider?tabs=windows&pivots=b2c-custom-policy