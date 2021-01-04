
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
module Network.Web.API where

import Data.Text(Text)
import Network.Web.Types
import Servant as S
import qualified Servant.Auth as SA
import Servant.Auth.Server as SAS

-- * Types

type LoginAPI =
  Summary
    "Allows users to login passing in credentials. If successful, this will set cookies \
    \ containing user's data in the form of JWT token."
    :> "signin"
    :> ReqBody '[JSON] Credentials
    :> Post
         '[JSON]
         ( Headers
             '[ Header "Set-Cookie" SetCookie,
                Header "Set-Cookie" SetCookie
              ]
             NoContent
         )

type RegisterAPI =
  Summary
  "User registration endpoint. Registration is successful iff. the user \
  \ provides a valid signed token, which is provided by another user \
  \ (see the @/tokens@ endpoint)."
  :> "signup"
  :> ReqBody '[JSON] UserRegistration
  :> Post '[JSON] NoContent

type TokensAPI =
  Summary
  "Registration tokens creation endpoint. An already authenticated user can retrieve tokens to share with \
  \ other users and let them register with this app."
  :> "tokens"
  :> Get '[OctetStream] SerializedToken


type AuthAPI =
  Summary
    "A endpoint to validate authenticated access. This is expected to be used by a reverse proxy which can query that endpoint, \
    \ passing an arbitrary target path. This server will verify the passed credentials and potentially return a www-authenticate \
    \ header to request authentication."
    :> "auth"
    :> CaptureAll "path" Text
    :> Get '[JSON] (Headers '[Header "www-authenticate" String] NoContent)

-- endpoints are protected with JWT and Cookie authentication scheme
type Protected = Auth '[SA.JWT, SA.Cookie, SA.BasicAuth] AuthenticationToken

-- | Authentication endpoint
-- this provides 2 authentication schemes for users:
--
--  * `JWT`: Expects an @Authorization: Bearer XXXX@ header in the query with claims
--    of the shape of `AuthenticationToken`. This should be provided by an external auth
--    provider
--  * `BasicAuth`: Expects an @Authorization: Basic XXXX@ header in the query where @XXX@
--    is a hashed login:password pair. This is useful only in testing and staging context.
type AuthAPIServer =
  LoginAPI
  :<|> RegisterAPI
  :<|> Protected :> TokensAPI
  :<|> Protected :> Header "x-original-method" Text :> AuthAPI