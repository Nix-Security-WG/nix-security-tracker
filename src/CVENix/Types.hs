module CVENix.Types where

import Data.Text (Text)
import CVENix.CVE

data Advisory = Advisory
  -- id is for example CVE is, later maybe GHSA etc
  { _advisory_id :: Text
  , _advisory_productName :: Maybe Text
  , _advisory_versions :: Maybe [Version]
  } deriving (Show, Eq, Ord)

data Match = Match
  { _match_pname :: Text
  , _match_drv :: Text
  , _match_advisory :: Advisory
  } deriving (Show, Eq, Ord)

newtype Derivation = Derivation { unDerivation :: Text } deriving (Show, Eq, Ord)

data DerivationData = DerivationData
  { _drv_path :: Text
  -- Context is what drvs this drv depends on
  , _drv_context :: [Derivation]
  } deriving (Show, Eq, Ord)

data InternalData = InternalData
  { _internaldata_drvdata :: DerivationData
  , _internaldata_advisory :: Advisory
  , _internaldata_packageName :: Text
  } deriving (Show, Eq, Ord)

data SemVer = SemVer
  { _semver_major :: Text
  , _semver_minor :: Text
  , _semver_patch :: Maybe Text
  } deriving (Show, Eq, Ord)

data VersionData = VersionData
  { _versiondata_semver :: Maybe Text
  , _versiondata_vuln :: Maybe Text
  } deriving (Show, Eq, Ord)
