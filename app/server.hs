import Data.Aeson (eitherDecode, encode)
import Data.Text(pack)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Text.Lazy as Text
import Data.Text.Lazy.Encoding (encodeUtf8)
import Network.Web.Auth
import System.Environment (lookupEnv)

main :: IO ()
main = do
  key <- getKey =<< lookupEnv "AUTH_SERVER_JWK"
  port <- maybe defaultPort read <$> lookupEnv "AUTH_SERVER_PORT"
  passwords <- lookupEnv "AUTH_SERVER_PASSWORDS"
  serverName <- maybe "localhost" pack <$> lookupEnv "AUTH_SERVER_NAME"
  startServer (AuthConfig port serverName passwords key) >>= waitServer
  where
    getKey Nothing = do
      jwk <- makeNewKey
      BS.writeFile ".auth-server.jwk" $ LBS.toStrict $ encode jwk
      pure jwk
    getKey (Just k) = either (error "environment variable 'AUTH_SERVER_JWK' is not set to a valid JWK key: ") pure (eitherDecode $ encodeUtf8 $ Text.pack k)
