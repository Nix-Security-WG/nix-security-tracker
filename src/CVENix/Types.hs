{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DeriveGeneric #-}
module CVENix.Types where

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Read as TR
import Control.Monad.Log
import Prettyprinter
import Control.Monad.IO.Class
import GHC.Generics

type LogT m ann = (MonadLog (WithSeverity (Doc ann)) m, MonadIO m)

data Version = Version
  { _version_version :: Text
  , _version_status :: Text
  , _version_type :: Maybe Text
  , _version_lessThan :: Maybe Text
  , _version_lessThanOrEqual :: Maybe Text
  , _version_changes :: Maybe [Change]
  } deriving (Show, Eq, Ord, Generic)

data Change = Change
  { _change_at :: Text
  , _change_status :: Text
  } deriving (Show, Eq, Ord, Generic)


data Parameters = Parameters
  { debug :: !Bool
  , sbom :: !String
  , path :: !(Maybe String)
  , timeInfo :: Bool
  } deriving (Show, Eq, Ord)


data LocalVuln = LocalVuln
  { _vuln_endVersionIncluding :: Maybe Text
  , _vuln_endVersionExcluding :: Maybe Text
  , _vuln_product :: Maybe Text
  , _vuln_cveId :: Text
  , _vuln_severity :: Maybe Text
  } deriving (Show, Eq, Ord)

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
  { _semver_major :: Int
  , _semver_minor :: Int
  , _semver_patch :: Maybe Int
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

prettySemVer :: SemVer -> String
prettySemVer (SemVer major minor c) = (show major) <> "." <> (show minor) <> case c of
                                                         Nothing -> ""
                                                         Just d -> "." <> (show d)

splitSemVer :: Text -> Maybe SemVer
splitSemVer v = do
    let t = T.splitOn "." v
    case t of
      [major, minor] -> do
          let maj = getInt major
              min' = getInt minor
          case (maj, min') of
            (Just a, Just b) -> Just $ SemVer a b Nothing
            _ -> Nothing
      [major, minor, patch] -> do
          let maj = getInt major
              min' = getInt minor
          case (maj, min') of
            (Just a, Just b) -> Just $ SemVer a b (getInt patch)
            _ -> Nothing
      _ -> Nothing
    where
        getInt a = case TR.decimal a of
                     Left _ -> Nothing
                     Right b -> Just $ fst b
