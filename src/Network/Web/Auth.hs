{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

{--| Basic server for authenticating HTTP request using JWT or login.

See <https://docs.servant.dev/en/latest/tutorial/Authentication.html servant documentation> And
<https://github.com/haskell-servant/servant-auth#readme servant-auth> package documentation for
more details.
-}
module Network.Web.Auth
  ( AuthServer (..),
    AuthConfig (..),
    AuthenticatedUser (..),
    Credentials (..),
    UserRegistration(..),
    defaultConfig,
    defaultPort,
    getServerPort,
    startServer,
    waitServer,
    stopServer,

    -- * Client
    validate,
    login,

    -- * Passwords File Operations
    makeDB,
  )
where

import Control.Concurrent.Async
  (     async,
  )
import Control.Monad.Trans
import Crypto.JOSE
import Data.Aeson
import Data.Proxy
import Data.Text(Text)
import Network.Web.DB
import Network.Web.Types
import Data.Text.Encoding
  (
    encodeUtf8,
  )
import GHC.Generics
import Network.Wai.Handler.Warp
import Network.CORS
import Preface.Log
import qualified Preface.Server as Server
import Servant as S
import Servant.Auth as SA
import Servant.Auth.Server as SAS
import Servant.Client

-- * Types

-- | An instance of authentication server.
-- This object is used to control the server, mainly waiting for it
-- and stopping it
data AuthServer = AuthServer
  { authServerBase :: Server.AppServer,
    authServerConfig :: AuthConfig
  }

getServerPort :: AuthServer -> Int
getServerPort (AuthServer app _) = Server.serverPort app

-- | Server configuration
data AuthConfig = AuthConfig
  { -- | the actual port server is listening on
    authServerPort :: Port,
    -- | The server fully qualified domain name
    authServerName :: Text,
    -- | Optional file to use for authenticating users with Basic auth
    --  scheme. File should contain one login:password per line, with
    --  password being encrypted using publicAuthKey
    passwordsFile :: Maybe FilePath,
    -- | Time interval (in us) between checks for passwords file changes
    reloadInterval :: Int,
    -- | The key used to validate and sign authentication tokens
    publicAuthKey :: JWK
  }
  deriving (Eq, Show, Generic)

instance ToJSON AuthConfig

instance FromJSON AuthConfig

defaultConfig :: JWK -> AuthConfig
defaultConfig = AuthConfig defaultPort "localhost:3001" Nothing 5000000

defaultPort :: Int
defaultPort = 3001

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
  "User registration endpoint. Registration is successful iff. the user provides a valid signed token, which is provided by another user (see the @/tokens@ endpoint)."
  :> "signup"
  :> ReqBody '[JSON] UserRegistration
  :> Post '[JSON] NoContent

type AuthAPI =
  Summary
    "A endpoint to validate authenticated access. This is expected to be used by a reverse proxy which can query that endpoint, \
    \ passing an arbitrary target path. This server will verify the passed credentials and potentially return a www-authenticate \
    \ header to request authentication."
    :> "auth"
    :> CaptureAll "path" Text
    :> Get '[JSON] (Headers '[Header "www-authenticate" String] NoContent)

-- endpoints are protected with JWT and Cookie authentication scheme
type Protected = Auth '[SA.JWT, SA.Cookie, SA.BasicAuth] AuthenticatedUser

-- | Authentication endpoint
-- this provides 2 authentication schemes for users:
--
--  * `JWT`: Expects an @Authorization: Bearer XXXX@ header in the query with claims
--    of the shape of `AuthenticatedUser`. This should be provided by an external auth
--    provider
--  * `BasicAuth`: Expects an @Authorization: Basic XXXX@ header in the query where @XXX@
--    is a hashed login:password pair. This is useful only in testing and staging context.
type AuthAPIServer =
  LoginAPI
  :<|> RegisterAPI
  :<|> Protected :> Header "x-original-method" Text :> AuthAPI

-- ** Basic Client, for testing purpose

type AuthAPIClient =
  LoginAPI :<|> S.BasicAuth "test" AuthenticatedUser :> AuthAPI

validate :: BasicAuthData -> [Text] -> ClientM (Headers '[Header "www-authenticate" String] NoContent)
login ::
  Credentials ->
  ClientM
    ( Headers
        '[ Header "Set-Cookie" SetCookie,
           Header "Set-Cookie" SetCookie
         ]
        NoContent
    )
login :<|> validate = client (Proxy :: Proxy AuthAPIClient)

-- * Server

-- ** Server Handler

loginS ::
  AuthDB ->
  CookieSettings ->
  JWTSettings ->
  Credentials ->
  Handler (Headers '[Header "Set-Cookie" SetCookie, Header "Set-Cookie" SetCookie] NoContent)
loginS authDB cs js (Credentials l p) = do
  res <- liftIO $ authCheck authDB (BasicAuthData (encodeUtf8 l) (encodeUtf8 p))
  case res of
    Authenticated usr -> do
      mApplyCookies <- liftIO $ acceptLogin cs js usr
      case mApplyCookies of
        Nothing -> throwError err401
        Just applyCookies -> return $ applyCookies NoContent
    _ -> throwError err401

registerS
        :: AuthDB -> JWTSettings -> UserRegistration -> Handler NoContent
registerS _authDB jwts UserRegistration{..} = do
  usr <- liftIO $ SAS.verifyJWT jwts regToken
  case usr of
    Nothing -> throwError err403
    Just AUser{} -> pure NoContent

-- | A simple handler that only checks the result of authentication is `Authenticated`
-- TODO: validate claims
server ::
  AuthResult val ->
  Maybe Text -> path -> Handler (Headers '[Header "www-authenticate" String] NoContent)
server _ (Just "OPTIONS") _ = pure $ noHeader NoContent
server (Authenticated _) _ _ = handleValidate
  where
    handleValidate :: Handler (Headers '[Header "www-authenticate" String] NoContent)
    handleValidate = pure $ noHeader NoContent
server _ _ _ = throwAll err401 {errHeaders = [("www-authenticate", "Basic realm=\"test\"")]}

-- | Starts server with given configuration
startServer :: AuthConfig -> IO AuthServer
startServer conf@AuthConfig {authServerPort, authServerName, publicAuthKey, passwordsFile, reloadInterval} = do
  authDB <- readDB passwordsFile
  appServer <- Server.startAppServer authServerName NoCORS authServerPort (mkApp publicAuthKey authDB)
  reloadThread <- async $ reloadDBOnFileChange passwordsFile reloadInterval authDB
  pure $ AuthServer appServer { Server.serverThread = reloadThread : Server.serverThread appServer } conf


-- | Stops given server if it is runninng
stopServer :: AuthServer -> IO ()
stopServer (AuthServer appServer _) = Server.stopServer appServer

waitServer :: AuthServer -> IO ()
waitServer (AuthServer appServer _) = Server.waitServer appServer

-- make actual `Application`
mkApp :: JWK -> AuthDB -> LoggerEnv -> IO Application
mkApp key authDB _ = do
  let jwtCfg = defaultJWTSettings key
      authCfg = authCheck authDB
      cookieCfg = defaultCookieSettings
      cfg = jwtCfg :. cookieCfg :. authCfg :. EmptyContext
      api = Proxy :: Proxy AuthAPIServer
  pure $ serveWithContext api cfg (loginS authDB cookieCfg jwtCfg :<|> registerS authDB jwtCfg :<|> server)
