# JWTechniques

Tool to manipulate JSON Web Token and see if they can be exploited


## Commands

### Sign

Take a JWT and a private key and sign it according to the algorithm used

### Magic

Take a JWT, parse it and gives several proposition on how to exploit it.

### Things it looks for:
- In all case
    - Try to change the algo to "none"
- Presence of a "JKU" header
    - JKU header injection
- Presence of a "KID" header
    - Try common injection to trigger errors
- If "alg" is "RS256"
    - Algorithm confusion
    - Inject public key in header


# RoadMap

- Add others ways to
- Generate all kind of priv/public keys
- Implement attacks
  - Algo confusion
  - Public key in header
  - Finish JKU injection
  - KID injection
