{-# LANGUAGE DataKinds #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
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
    module Network.Web.Types,
    defaultConfig,
    defaultPort,
    getServerPort,
    startServer,
    waitServer,
    stopServer,

    -- * Client
    validate,
    register,
    login,

    -- * Passwords File Operations
    makeDB,

    -- * Configuration
    makeConfig,
  )
where

import Control.Lens (re, (^.))
import Control.Monad.Trans
import Crypto.JOSE
import Data.Aeson
import Data.Maybe
import qualified Data.ByteString.Lazy as LBS
import Data.Proxy
import Data.Text (Text)
import Data.Text.Encoding
  ( encodeUtf8,
  )
import Data.Text.Strict.Lens (utf8)
import Network.CORS
import Network.Web.API
import Network.Web.Config
import Network.Web.DB
import Network.Web.OpenApi
import Network.Web.Types
import Preface.Codec
import Preface.Log
import qualified Preface.Server as Server
import Servant as S
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

-- ** Basic Client, for testing purpose

type AuthAPIClient =
  LoginAPI :<|> RegisterAPI :<|> S.BasicAuth "test" AuthenticationToken :> AuthAPI

validate :: BasicAuthData -> [Text] -> ClientM (Headers '[Header "www-authenticate" String] NoContent)
register :: UserRegistration -> ClientM NoContent
login ::
  Credentials ->
  ClientM
    ( Headers
        '[ Header "Set-Cookie" SetCookie,
           Header "Set-Cookie" SetCookie
         ]
        NoContent
    )
login :<|> register :<|> validate = client (Proxy :: Proxy AuthAPIClient)

-- * Server

-- ** Server Handler

loginS ::
  AuthDB ->
  CookieSettings ->
  JWTSettings ->
  Credentials ->
  Handler (Headers '[Header "Set-Cookie" SetCookie, Header "Set-Cookie" SetCookie] NoContent)
loginS authDB cs js (Credentials l p) = do
  res <- runDB authDB (authCheck (BasicAuthData (encodeUtf8 l) (encodeUtf8 p)))
  case res of
    Authenticated usr -> do
      mApplyCookies <- liftIO $ acceptLogin cs js usr
      case mApplyCookies of
        Nothing -> throwError err401
        Just applyCookies -> return $ applyCookies NoContent
    _ -> throwError err401

keysS ::
  JWTSettings ->
  Handler [JWK]
keysS js = do
  let JWKSet keys = validationKeys js
  pure $ mapMaybe (^. asPublicKey) keys

registerS ::
  AuthDB -> JWTSettings -> UserRegistration -> Handler NoContent
registerS authDB jwts UserRegistration {..} = do
  usr <- liftIO $ SAS.verifyJWT jwts (unToken regToken)
  case usr of
    Nothing -> throwError err403
    Just RegToken {} -> do
      res <- runDB authDB (registerUser regLogin regPassword)
      case res of
        Left _ -> throwError err400
        Right _ -> pure NoContent

tokensS ::
  JWTSettings -> AuthResult AuthenticationToken -> Handler SerializedToken
tokensS jwts (Authenticated AuthToken {auID}) = do
  tid <- liftIO $ genRandomBaseHex 16
  let regToken = RegToken auID (TokenID $ Bytes tid)
  res <- liftIO $ makeJWT regToken jwts Nothing
  case res of
    Left _err -> throwError err500
    Right tok -> pure $ SerializedToken (LBS.toStrict tok)
tokensS _ _ = throwError err403

-- | A simple handler that only checks the result of authentication is `Authenticated`
-- TODO: validate claims
server ::
  AuthResult val ->
  Maybe Text ->
  path ->
  Handler (Headers '[Header "www-authenticate" String] NoContent)
server _ (Just "OPTIONS") _ = pure $ noHeader NoContent
server (Authenticated _) _ _ = handleValidate
  where
    handleValidate :: Handler (Headers '[Header "www-authenticate" String] NoContent)
    handleValidate = pure $ noHeader NoContent
server _ _ _ = throwAll err401 {errHeaders = [("www-authenticate", "Basic realm=\"test\"")]}

data Startup = Startup {startName :: Text, startPort :: Int, startKey :: JWK}

instance ToJSON Startup where
  toJSON Startup {..} = object ["start_name" .= startName, "start_port" .= startPort, "start_key" .= (startKey ^. (thumbprint @SHA256) . re (base64url . digest) . utf8)]

-- | Starts server with given configuration
startServer :: AuthConfig -> IO AuthServer
startServer conf@AuthConfig {authServerPort, authServerName, publicAuthKey, passwordsFile} = do
  authDB <- readDB passwordsFile
  appServer <- Server.startAppServer authServerName NoCORS authServerPort (mkApp publicAuthKey authDB)
  logInfo (Server.serverLogger appServer) $ Startup (Server.serverName appServer) (Server.serverPort appServer) publicAuthKey
  pure $ AuthServer appServer conf

-- | Stops given server if it is runninng
stopServer :: AuthServer -> IO ()
stopServer (AuthServer appServer _) = Server.stopServer appServer

waitServer :: AuthServer -> IO ()
waitServer (AuthServer appServer _) = Server.waitServer appServer

type SwaggerAPI =
  "swagger.json" :> Get '[JSON] Swagger

-- make actual `Application`
mkApp :: JWK -> AuthDB -> LoggerEnv -> IO Application
mkApp key authDB _ = do
  let jwtCfg = defaultJWTSettings key
      authCfg = runDB @IO authDB . authCheck
      cookieCfg = defaultCookieSettings
      cfg = jwtCfg :. cookieCfg :. authCfg :. EmptyContext
      api = Proxy :: Proxy (SwaggerAPI :<|> AuthAPIServer)
  pure $ serveWithContext api cfg (pure authSwagger :<|> loginS authDB cookieCfg jwtCfg :<|> registerS authDB jwtCfg :<|> keysS jwtCfg :<|> tokensS jwtCfg :<|> server)
