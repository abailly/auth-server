{-# LANGUAGE DeriveGeneric #-}

module Network.Web.Config where

import Data.Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Functor
import Data.Maybe (fromMaybe)
import Data.Text (Text, pack)
import qualified Data.Text.Lazy as Text
import Data.Text.Lazy.Encoding (encodeUtf8)
import GHC.Generics (Generic)
import Network.Wai.Handler.Warp (Port)
import Network.Web.DB (makeDB)
import Network.Web.Types
import System.Environment (lookupEnv)
import Text.Read (readMaybe)

-- | Server configuration
data AuthConfig = AuthConfig
  { -- | the actual port server is listening on
    authServerPort :: !Port,
    -- | The server fully qualified domain name
    authServerName :: !Text,
    -- | Optional file to use for authenticating users with Basic auth
    --  scheme. File should contain one login:password per line, with
    --  password being encrypted using publicAuthKey
    passwordsFile :: !FilePath,
    -- | The key used to validate and sign authentication tokens
    publicAuthKey :: !JWK
  }
  deriving (Eq, Show, Generic)

instance ToJSON AuthConfig

instance FromJSON AuthConfig

defaultConfig :: JWK -> AuthConfig
defaultConfig = AuthConfig defaultPort "localhost:3001" ".passwords"

defaultPort :: Int
defaultPort = 3001

makeConfig :: FilePath -> IO AuthConfig
makeConfig jwkFile = do
  key <- lookupEnv "AUTH_SERVER_JWK" >>= getKey
  port <- lookupEnv "AUTH_SERVER_PORT" <&> maybe defaultPort readPort
  adminPassword <- lookupEnv "AUTH_SERVER_ADMIN_PASSWORD"
  passwords <- lookupEnv "AUTH_SERVER_PASSWORDS" >>= defaultPasswordFile adminPassword
  serverName <- lookupEnv "AUTH_SERVER_NAME" <&> maybe "localhost" pack
  pure $ AuthConfig port serverName passwords key
  where
    readPort = fromMaybe (error "incorrect port value in environment variable AUTH_SERVER_PORT") . readMaybe

    defaultPasswordFile Nothing Nothing = error "neither environment variable 'AUTH_SERVER_PASSWORDS' nor 'AUTH_SERVER_ADMIN_PASSWORD' are set, define one of them"
    defaultPasswordFile (Just pwd) Nothing = do
      makeDB ".passwords" ("admin:" <> pack pwd <> "\n")
      pure ".passwords"
    defaultPasswordFile _ (Just fp) = pure fp

    getKey Nothing = do
      jwk <- makeNewKey
      BS.writeFile jwkFile $ LBS.toStrict $ encode jwk
      pure jwk
    getKey (Just k) = either (error "environment variable 'AUTH_SERVER_JWK' is not set to a valid JWK key: ") pure (eitherDecode $ encodeUtf8 $ Text.pack k)
