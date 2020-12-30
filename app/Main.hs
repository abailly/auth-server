{-# LANGUAGE OverloadedStrings #-}

module Main where

import App
import Control.Applicative
import Control.Concurrent.STM
import Control.Monad.Reader
import qualified Data.HashMap.Strict as HM
import Data.Semigroup ((<>))
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.IO as TLIO
import Lib
import Options.Applicative
import qualified Web.Scotty.Trans as S

main :: IO ()
main = runWebApp =<< execParser opts
  where
    opts =
      info
        (authOptions <**> helper)
        ( fullDesc
            <> progDesc "Start a web server authenticating http requests."
            <> header "auth - Generic Authentication Server"
        )

runWebApp :: AuthOptions -> IO ()
runWebApp opts = do
  sync <- newTVarIO initialState

  -- 'runActionToIO' is called once per action.
  let runActionToIO m = runReaderT (runWebM m) sync
  passwordDB <- readPasswordsFile $ passwordFile opts
  S.scottyT (port opts) runActionToIO $ app passwordDB

readPasswordsFile :: FilePath -> IO PasswordDB
readPasswordsFile pwdFile = do
  fileContent <- TLIO.readFile pwdFile
  return (parsePasswordsContent fileContent)

data AuthOptions = AuthOptions
  { port :: Int,
    passwordFile :: FilePath
  }

authOptions :: Parser AuthOptions
authOptions =
  AuthOptions
    <$> option
      auto
      ( long "port"
          <> help "Port to listen to."
          <> showDefault
          <> value 3001
          <> metavar "INT"
      )
    <*> strOption
      ( long "password-file"
          <> help "File containing the passwords."
          <> showDefault
          <> value ".passwords"
          <> metavar "DIRECTORY"
      )
