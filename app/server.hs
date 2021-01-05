import Data.Aeson (eitherDecode, encode)
import Data.Text(pack)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Text.Lazy as Text
import Data.Text.Lazy.Encoding (encodeUtf8)
import Network.Web.Auth
import System.Environment (lookupEnv)
import System.IO

main :: IO ()
main = do
  hSetBuffering stdout NoBuffering
  key <- getKey =<< lookupEnv "AUTH_SERVER_JWK"
  port <- maybe defaultPort read <$> lookupEnv "AUTH_SERVER_PORT"
  adminPassword <- lookupEnv "AUTH_SERVER_ADMIN_PASSWORD"
  passwords <- defaultPasswordFile adminPassword =<< lookupEnv "AUTH_SERVER_PASSWORDS"
  serverName <- maybe "localhost" pack <$> lookupEnv "AUTH_SERVER_NAME"
  startServer (AuthConfig port serverName passwords key) >>= waitServer
  where
    defaultPasswordFile Nothing Nothing = error "neither environment variable 'AUTH_SERVER_PASSWORDS' nor 'AUTH_SERVER_ADMIN_PASSWORD' are set, define one of them"
    defaultPasswordFile (Just pwd) Nothing = do
      makeDB ".passwords" ("admin:" <> pack pwd <> "\n")
      pure ".passwords"
    defaultPasswordFile _ (Just fp) = pure fp
    getKey Nothing = do
      jwk <- makeNewKey
      BS.writeFile ".auth-server.jwk" $ LBS.toStrict $ encode jwk
      pure jwk
    getKey (Just k) = either (error "environment variable 'AUTH_SERVER_JWK' is not set to a valid JWK key: ") pure (eitherDecode $ encodeUtf8 $ Text.pack k)
