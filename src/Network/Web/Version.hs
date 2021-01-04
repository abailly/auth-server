module Network.Web.Version
  (
    authVersion, authVersionTH,
    module Data.Version
  )
where

import Data.Version
import Paths_auth_server (version)
import Language.Haskell.TH

-- | The current authenticatoin server's version
--
-- This is the code representation of the version string definied in the cabal file or
-- `package.json`
authVersion :: Version
authVersion = version

authVersionTH :: Q Type
authVersionTH = pure (LitT (StrTyLit $ showVersion authVersion))
