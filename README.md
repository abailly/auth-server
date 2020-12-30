# auth-server

A standalone Servant-based authentication server.

- I needed a solution to authenticate users for [sensei](https://github.com/abailly/sensei),
- Authentication in web apps is a PITA,
- Setting up OAuth2 on the server-side is not that easy, and doing so in Haskell is even less easy,
- I wanted something that could authenticate users through web-based forms and UI, and also support tokens for CLI usage,
- I pondered whether or not I wanted to use [Keycloak](https://www.keycloak.org/) and decided I did want that much complexity yet,
- I ended up reusing a simple solution I previously implemented, adding support for login form and sqlite-based storage,
- As this is independent from the main service that uses it, I expect to be able to grow it until it gets unwieldy and I need to switch to an industrial-strength solution.
