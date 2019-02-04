# SSO I heard you like SAML - Points: 200

### Description:

I showed my passport, but I can't seem to get the data I need! (My login credentials: joe:letmein3)

### Hints

 - Can you read the data passed from the SimpleSamlPHP identity provider to the webapp? Try base64 decoding.
 - Is there anything in the SamlResponse that can be changed?

### Solution

Note: This was an on-demand challange that spins up a personalized web service for the player.

Write a script to login, read the SAMLResponse, decode, set admin true, encode, post.

### Flag: `ACI{635c0b463fd257dd22ad3831f43}`

