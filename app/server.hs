import Network.Web.Auth
import System.IO

main :: IO ()
main = do
  hSetBuffering stdout NoBuffering
  config <- makeConfig
  startServer config >>= waitServer
