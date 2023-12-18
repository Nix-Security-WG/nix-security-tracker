-- SPDX-FileCopyrightText: 2023 Arnout Engelen <arnout@bzzt.net>
-- SPDX-FileCopyrightText: 2023 Dylan Green <dylan.green@obsidian.systems>
--
-- SPDX-License-Identifier: MIT

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DeriveGeneric #-}
module LocalSecurityScanner.Types where

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Read as TR
import Control.Monad.Log
import Prettyprinter
import Control.Monad.IO.Class

class Default a where
    def :: a

type LogT m ann = (MonadLog (WithSeverity (Doc ann)) m, MonadIO m)

data Parameters = Parameters
  { debug :: !Bool
  , sbom :: !String
  , path :: !(Maybe String)
  , timeInfo :: Bool
  , excludeVendors :: Maybe [String]
  , securityTrackerUrl :: Maybe String
  } deriving (Show, Eq, Ord)


data LocalVuln = LocalVuln
  { _vuln_startVersionIncluding :: Maybe Text
  , _vuln_startVersionExcluding :: Maybe Text
  , _vuln_endVersionIncluding :: Maybe Text
  , _vuln_endVersionExcluding :: Maybe Text
  , _vuln_product :: Maybe Text
  , _vuln_cveId :: Text
  , _vuln_severity :: Maybe Text
  } deriving (Show, Eq, Ord)

newtype Derivation = Derivation { unDerivation :: Text } deriving (Show, Eq, Ord)

data DerivationData = DerivationData
  { _drv_path :: Text
  -- Context is what drvs this drv depends on
  , _drv_context :: [Derivation]
  } deriving (Show, Eq, Ord)

data SemVer = SemVer
  { _semver_major :: Int
  , _semver_minor :: Int
  , _semver_patch :: Maybe Int
  , _semver_patchupdate :: Maybe Int
  } deriving (Show, Eq, Ord)

instance Default Parameters where
    def = Parameters False "test.sbom" Nothing False Nothing Nothing


prettySemVer :: SemVer -> String
prettySemVer (SemVer major minor patch patchupdate) = (show major) <> "." <> (show minor) <> case patch of
                                                         Nothing -> ""
                                                         Just p -> "." <> (show p) <> case patchupdate of
                                                           Nothing -> ""
                                                           Just pu -> "." <> (show pu)

splitSemVer :: Text -> Maybe SemVer
splitSemVer v = do
    let t = T.splitOn "." v
    case t of
      [major, minor] -> do
          let maj = getInt major
              min' = getInt minor
          case (maj, min') of
            (Just a, Just b) -> Just $ SemVer a b Nothing Nothing
            _ -> Nothing
      [major, minor, patch] -> do
          let maj = getInt major
              min' = getInt minor
          case (maj, min') of
            (Just a, Just b) -> Just $ SemVer a b (getInt patch) Nothing
            _ -> Nothing
      [major, minor, patch, patchupdate] -> do
          let maj = getInt major
              min' = getInt minor
          case (maj, min') of
            (Just a, Just b) -> Just $ SemVer a b (getInt patch) (getInt patchupdate)
            _ -> Nothing
      _ -> Nothing
    where
        getInt a = case TR.decimal a of
                     Left _ -> Nothing
                     Right b -> Just $ fst b
