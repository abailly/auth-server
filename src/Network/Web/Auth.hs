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

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async
  (     async,
  )
import Control.Exception (IOException, catch, throwIO)
import Control.Monad (forever, when, foldM)
import Control.Monad.Trans
import System.Random
import Crypto.Hash
import Crypto.JOSE
import Crypto.KDF.BCrypt
import Data.Aeson
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.IORef
import qualified Data.Map as M
import Data.Proxy
import Data.Text(Text)
import qualified Data.Text as Text
import Data.Text.Encoding
  ( decodeUtf8,
    encodeUtf8,
  )
import qualified Data.Text.IO as Text
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

-- Tokens structure from AWS
-- AWS ID Token structure
-- {
-- "sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
-- "aud": "xxxxxxxxxxxxexample",
-- "email_verified": true,
-- "token_use": "id",
-- "auth_time": 1500009400,
-- "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
-- "cognito:username": "janedoe",
-- "exp": 1500013000,
-- "given_name": "Jane",
-- "iat": 1500009400,
-- "email": "janedoe@example.com"
-- }

-- AWS Access Token payload

-- {
--     "auth_time": 1500009400,
--     "exp": 1500013000,
--     "iat": 1500009400,
--     "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
--     "scope": "aws.cognito.signin.user.admin",
--     "sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
--     "token_use": "access",
--     "username": "janedoe@example.com"
-- }

-- | Dead simple payload attached to JWT
-- TODO: replace with actual payload from auth provider
data AuthenticatedUser = AUser
  { auID :: Int,
    auOrgID :: Int
  }
  deriving (Show, Generic)

instance ToJSON AuthenticatedUser

instance FromJSON AuthenticatedUser

instance ToJWT AuthenticatedUser

instance FromJWT AuthenticatedUser

type Login = ByteString

type AuthDB = IORef (M.Map Login UserData)

data UserData = UserData { userSalt :: ByteString,
                           userPassword :: ByteString,
                           userAuth :: AuthenticatedUser }

-- ** User/Password Authentication

authCheck ::
  AuthDB ->
  BasicAuthData ->
  IO (AuthResult AuthenticatedUser)
authCheck authDB (BasicAuthData ident password) =
  readIORef authDB
    >>= pure . maybe SAS.NoSuchUser checkPassword . M.lookup ident
  where
    checkPassword UserData{..} =
      let encryptedPassword = encrypt userSalt password
      in
        if encryptedPassword == userPassword
        then SAS.Authenticated userAuth
        else SAS.BadPassword


encrypt :: ByteString -> ByteString -> ByteString
encrypt salt = bcrypt cost salt

cost :: Int
cost = 10

-- | Utility function to create a new passwords file from
-- pairs of cleartext `login:pwd` one per line
makeDB :: FilePath -> Text -> IO ()
makeDB file pwds = do
  let encodeLogin lns (l : p : _) = do
        g <- newStdGen
        let s = BS.pack $ take 16 $ randoms g
            ln = l <> ":" <> decodeUtf8 (B64.encode s) <> ":" <> decodeUtf8 (B64.encode (encrypt s (encodeUtf8 p)))
        pure (ln : lns)
      encodeLogin _ other = throwIO $ userError $ "invalid password entry " <> show other
  l <- foldM encodeLogin [] $
       fmap (Text.splitOn ":") $
       Text.lines pwds
  Text.writeFile file (Text.unlines l)


readDB :: Maybe FilePath -> IO AuthDB
readDB Nothing = newIORef M.empty
readDB (Just pwdFile) = newIORef =<< readPasswordsFile pwdFile

readPasswordsFile :: FilePath -> IO (M.Map Login UserData)
readPasswordsFile pwdFile =
  M.fromList
  . fmap (\ ((l,s,p),u) -> (l, UserData s p u))
    . flip zip (fmap (flip AUser 1) [1 ..])
    . fmap (\(l : s : p : _) -> (encodeUtf8 l, either (const "") id $ B64.decode $ encodeUtf8 s, either (const "") id $ B64.decode $ encodeUtf8 p))
    . fmap (Text.splitOn ":")
    . Text.lines
    <$> Text.readFile pwdFile

type instance BasicAuthCfg = BasicAuthData -> IO (AuthResult AuthenticatedUser)

instance FromBasicAuthData AuthenticatedUser where
  fromBasicAuthData authData authCheckFunction = authCheckFunction authData

data Credentials = Credentials
  { credLogin :: Text,
    credPassword :: Text
  }
  deriving (Eq, Show, Generic)

instance ToJSON Credentials

instance FromJSON Credentials

type LoginAPI =
  Summary
    "Allows users to login passing in credentials. If successful, this will set cookies \
    \ containing user's data in the form of JWT token."
    :> "login"
    :> ReqBody '[JSON] Credentials
    :> Post
         '[JSON]
         ( Headers
             '[ Header "Set-Cookie" SetCookie,
                Header "Set-Cookie" SetCookie
              ]
             NoContent
         )

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

-- | Periodically checks passwords file for changes and update the in-memory
-- DB.
reloadDBOnFileChange :: Maybe FilePath -> Int -> AuthDB -> IO ()
reloadDBOnFileChange Nothing _ _ = pure ()
reloadDBOnFileChange (Just pwdFile) reloadInterval authDB = do
  h <- getHash
  forever $ go h
  where
    go h =
      ( do
          threadDelay reloadInterval
          h' <- getHash
          when (h /= h') $
            (readPasswordsFile pwdFile >>= atomicWriteIORef authDB)
      )
        `catch` \(e :: IOException) -> putStrLn (show e)

    getHash :: IO (Digest SHA1)
    getHash = hash <$> BS.readFile pwdFile

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
  pure $ serveWithContext api cfg (loginS authDB cookieCfg jwtCfg :<|> server)
