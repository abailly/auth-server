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
    defaultConfig,
    defaultPort,
    validate,
    startServer,
    waitServer,
    stopServer,

    -- * Passwords File Operations
    makeDB,
  )
where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async
  ( Async (..),
    async,
    cancel,
    waitAnyCancel,
  )
import Control.Exception (IOException, catch)
import Control.Monad (forever, when)
import Crypto.Hash
import Crypto.JOSE
import Crypto.KDF.BCrypt
import Data.Aeson
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Default
import Data.Functor (void)
import Data.IORef
import Data.Map as M
import Data.Proxy
import Data.Text as Text hiding (zip)
import Data.Text.Encoding
  ( decodeUtf8,
    encodeUtf8,
  )
import qualified Data.Text.IO as Text
import GHC.Generics
import Network.Wai.Handler.Warp
import Network.Wai.Middleware.RequestLogger
import Network.Wai.Middleware.RequestLogger.JSON
import Servant as S
import Servant.Auth as SA
import Servant.Auth.Server as SAS
import Servant.Client
import System.IO

-- * Types

-- | An instance of authentication server.
-- This object is used to control the server, mainly waiting for it
-- and stopping it
data AuthServer = AuthServer
  { threads :: [Async ()],
    authServerConfig :: AuthConfig
  }

-- | Server configuration
data AuthConfig = AuthConfig
  { -- | the actual port server is listening on
    authServerPort :: Port,
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
defaultConfig = AuthConfig defaultPort Nothing 5000000

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

type Password = ByteString

type AuthDB = IORef (Map (Login, Password) AuthenticatedUser)

-- ** User/Password Authentication

authCheck ::
  AuthDB ->
  BasicAuthData ->
  IO (AuthResult AuthenticatedUser)
authCheck authDB (BasicAuthData login password) =
  readIORef authDB
    >>= pure . maybe SAS.Indefinite Authenticated . M.lookup (login, encryptedPassword)
  where
    encryptedPassword = encrypt password

encrypt :: ByteString -> ByteString
encrypt = bcrypt cost salt

cost :: Int
cost = 10

salt :: ByteString
salt = "Pq1hYnZ3VlXX9I9Q"

-- | Utility function to create a new passwords file
makeDB :: FilePath -> Text -> IO ()
makeDB file pwds =
  Text.writeFile file $
    Text.unlines $
      fmap (\(l : p : _) -> l <> ":" <> decodeUtf8 (encrypt $ encodeUtf8 p)) $
        fmap (Text.splitOn ":") $
          Text.lines pwds

readDB :: Maybe FilePath -> IO AuthDB
readDB Nothing = newIORef M.empty
readDB (Just pwdFile) = newIORef =<< readPasswordsFile pwdFile

readPasswordsFile :: FilePath -> IO (Map (Login, Password) AuthenticatedUser)
readPasswordsFile pwdFile =
  M.fromList
    . flip zip (fmap (flip AUser 1) [1 ..])
    . fmap (\(l : rest) -> (encodeUtf8 l, encodeUtf8 $ Text.concat rest))
    . fmap (Text.splitOn ":")
    . Text.lines
    <$> Text.readFile pwdFile

type instance BasicAuthCfg = BasicAuthData -> IO (AuthResult AuthenticatedUser)

instance FromBasicAuthData AuthenticatedUser where
  fromBasicAuthData authData authCheckFunction = authCheckFunction authData

type AuthAPI = CaptureAll "path" Text :> Get '[JSON] (Headers '[Header "WWW-Authenticate" String] NoContent)

-- | Authentication endpoint
-- this provides 2 authentication schemes for users:
--
--  * `JWT`: Expects an @Authorization: Bearer XXXX@ header in the query with claims
--    of the shape of `AuthenticatedUser`. This should be provided by an external auth
--    provider
--  * `BasicAuth`: Expects an @Authorization: Basic XXXX@ header in the query where @XXX@
--    is a hashed login:password pair. This is useful only in testing and staging context.
type AuthAPIServer =
  Auth '[SA.JWT, SA.BasicAuth] AuthenticatedUser :> Header "x-original-method" Text :> AuthAPI

-- ** Basic Client, for testing purpose

type AuthAPIClient = S.BasicAuth "test" AuthenticatedUser :> AuthAPI

validate :: BasicAuthData -> [Text] -> ClientM (Headers '[Header "WWW-Authenticate" String] NoContent)
validate = client (Proxy :: Proxy AuthAPIClient)

-- * Server

-- ** Server Handler

-- | A simple handler that only checks the result of authentication is `Authenticated`
-- TODO: validate claims
server :: Server AuthAPIServer
server _ (Just "OPTIONS") _ = pure $ noHeader NoContent
server (Authenticated _) _ _ = handleValidate
  where
    handleValidate :: Handler (Headers '[Header "WWW-Authenticate" String] NoContent)
    handleValidate = pure $ noHeader NoContent
server _ _ _ = throwAll err401 {errHeaders = [("WWW-Authenticate", "Basic realm=\"test\"")]}

-- | Starts server with given configuration
startServer :: AuthConfig -> IO AuthServer
startServer conf@AuthConfig {authServerPort, publicAuthKey, passwordsFile, reloadInterval} = do
  authDB <- readDB passwordsFile
  let settings =
        setPort authServerPort $
          setBeforeMainLoop (LBS.hPutStr stderr (encode startupMessage <> "\n")) $
            defaultSettings
      runner =
        if authServerPort /= 0
          then pure (authServerPort, runSettings settings)
          else openFreePort >>= \(port, socket) -> pure (port, runSettingsSocket settings socket)

      startupMessage = object ["serverPort" .= authServerPort, "passwordsFile" .= passwordsFile]

  (port, appRunner) <- runner
  serverThread <- async $ appRunner =<< mkApp publicAuthKey authDB
  reloadThread <- async $ reloadDBOnFileChange passwordsFile reloadInterval authDB
  pure $ AuthServer [serverThread, reloadThread] (conf {authServerPort = port})

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
stopServer (AuthServer threads _) = mapM_ cancel threads

waitServer :: AuthServer -> IO ()
waitServer (AuthServer threads _) = void $ waitAnyCancel threads

-- make actual `Application`
mkApp :: JWK -> AuthDB -> IO Application
mkApp key authDB = do
  let jwtCfg = defaultJWTSettings key
      authCfg = authCheck authDB
      cfg = jwtCfg :. defaultCookieSettings :. authCfg :. EmptyContext
      api = Proxy :: Proxy AuthAPIServer
      doLog = mkRequestLogger $ def {outputFormat = CustomOutputFormatWithDetails formatAsJSON}
  logger <- doLog
  pure $ logger $ serveWithContext api cfg server
