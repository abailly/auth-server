import Network.Web.Auth
import System.IO

main :: IO ()
main = do
  hSetBuffering stdout NoBuffering
  config <- makeConfig ".auth-server.jwk"
  startServer config >>= waitServer
