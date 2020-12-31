module Network.Web.DB where

import Control.Concurrent (threadDelay)
import Control.Exception (IOException, catch, throwIO)
import Control.Monad (foldM, forever, when)
import Crypto.Hash
import Crypto.KDF.BCrypt
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.IORef
import qualified Data.Map as M
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding
  ( decodeUtf8,
    encodeUtf8,
  )
import qualified Data.Text.IO as Text
import Network.Web.Types
--import Preface.Log
import Servant as S
import Servant.Auth.Server as SAS
import System.Random

data AuthDB = AuthDB
  { dbFile :: FilePath,
    dbCache :: IORef (M.Map Login UserData)
  }

data UserData = UserData
  { userSalt :: ByteString,
    userPassword :: ByteString,
    userAuth :: AuthenticatedUser
  }

-- ** User/Password Authentication

authCheck ::
  AuthDB ->
  BasicAuthData ->
  IO (AuthResult AuthenticatedUser)
authCheck (AuthDB _ authDB) (BasicAuthData ident password) =
  readIORef authDB
    >>= pure . maybe SAS.NoSuchUser checkPassword . M.lookup ident
  where
    checkPassword UserData {..} =
      let encryptedPassword = encrypt userSalt password
       in if encryptedPassword == userPassword
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
        ln <- makeDBEntry l p
        pure (ln : lns)
      encodeLogin _ other = throwIO $ userError $ "invalid password entry " <> show other
  l <-
    foldM encodeLogin [] $
      fmap (Text.splitOn ":") $
        Text.lines pwds
  Text.writeFile file (Text.unlines l)

makeDBEntry :: Text -> Text -> IO Text
makeDBEntry l p = do
  g <- newStdGen
  let s = BS.pack $ take 16 $ randoms g
  pure $ l <> ":" <> decodeUtf8 (B64.encode s) <> ":" <> decodeUtf8 (B64.encode (encrypt s (encodeUtf8 p)))

data DBError
  = GenericDBError {reason :: Text}
  | DuplicateUserEntry Text
  deriving (Eq, Show)

registerUser :: AuthDB -> Text -> Text -> IO (Either DBError AuthenticatedUser)
registerUser (AuthDB pwdFile db) login pwd = do
  usrs <- readIORef db
  case M.lookup (encodeUtf8 login) usrs of
    Just _ -> undefined
    Nothing -> do
      e <- makeDBEntry login pwd
      Text.appendFile pwdFile (e <> "\n")
      readPasswordsFile pwdFile >>= atomicWriteIORef db
      fmap userAuth . maybe (Left $ GenericDBError "failed to register user") Right . M.lookup (encodeUtf8 login) <$> readIORef db

readDB :: Maybe FilePath -> IO AuthDB
readDB Nothing = AuthDB "" <$> newIORef mempty
readDB (Just pwdFile) = AuthDB pwdFile <$> (readPasswordsFile pwdFile >>= newIORef)

readPasswordsFile :: FilePath -> IO (M.Map Login UserData)
readPasswordsFile pwdFile =
  M.fromList
    . fmap (\((l, s, p), u) -> (l, UserData s p u))
    . flip zip (fmap (flip AUser 1) [1 ..])
    . fmap (\(l : s : p : _) -> (encodeUtf8 l, either (const "") id $ B64.decode $ encodeUtf8 s, either (const "") id $ B64.decode $ encodeUtf8 p))
    . fmap (Text.splitOn ":")
    . Text.lines
    <$> Text.readFile pwdFile

-- | Periodically checks passwords file for changes and update the in-memory
-- DB.
reloadDBOnFileChange :: Int -> AuthDB -> IO ()
reloadDBOnFileChange reloadInterval (AuthDB pwdFile authDB) = do
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
