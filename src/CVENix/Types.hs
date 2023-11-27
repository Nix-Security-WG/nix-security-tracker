module CVENix.Types where

import Data.Text (Text)
import CVENix.CVE

data Advisory = Advisory
  -- id is for example CVE is, later maybe GHSA etc
  { _advisory_id :: Text
  , _advisory_products :: [AdvisoryProduct]
  } deriving (Show, Eq, Ord)

data AdvisoryProduct = AdvisoryProduct
  { _advisory_product_productName :: Maybe Text
  , _advisory_product_defaultStatus :: Maybe Text
  , _advisory_product_versions :: Maybe [Version]
  } deriving (Show, Eq, Ord)

data Match = Match
  { _match_pname :: Text
  , _match_version :: Text
  , _match_drv :: Text
  , _match_advisory :: (Advisory, AdvisoryProduct)
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
  { _versiondata_semver :: Text
  , _versiondata_vuln :: Maybe VersionVuln
  , _versiondata_status :: Text
  } deriving (Show, Eq, Ord)

data VersionVuln
  = LessThan Text
  | LessThanOrEqual Text
  | Exact
  deriving (Show, Eq, Ord)
