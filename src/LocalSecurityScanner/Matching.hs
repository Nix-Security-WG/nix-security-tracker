-- SPDX-FileCopyrightText: 2023 Arnout Engelen <arnout@bzzt.net>
-- SPDX-FileCopyrightText: 2023 Dylan Green <dylan.green@obsidian.systems>
--
-- SPDX-License-Identifier: MIT

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE CPP #-}
module LocalSecurityScanner.Matching where

import LocalSecurityScanner.SBOM
import LocalSecurityScanner.Types
import LocalSecurityScanner.NVD
import LocalSecurityScanner.Utils
import LocalSecurityScanner.WebData

import Data.Char (isDigit)
import qualified Data.Set as Set
import qualified Data.Map as Map
import Data.Maybe
import qualified Data.Multimap.Set as SetMultimap
import Data.Text (Text)
import qualified Data.Text as T
import Control.Monad
import Control.Monad.Log
import Control.Monad.IO.Class
import Prettyprinter
import Control.Monad.Trans.Reader

data InventoryComponent = InventoryComponent
  { _inventorycomponent_pname :: Text
  , _inventorycomponent_version :: Maybe Text
  , _inventorycomponent_drv :: Text
  } deriving (Show)

data Match = Match
  { _match_name :: Text
  , _match_advisory_id :: Text
  , _match_severity :: Maybe Text
  , _match_version :: Maybe Text
  , _match_drv_path :: Text
  } deriving (Show)

createMatch :: Text -> Maybe Text -> Text -> LocalVuln -> Match
createMatch pname version drv_path vuln =
  Match pname (_vuln_cveId vuln) (_vuln_severity vuln) version drv_path

versionInRange :: Maybe Text -> LocalVuln -> Bool
versionInRange version vuln =
  let localver = version >>= splitSemVer
      rangeStartIncluding = (_vuln_startVersionIncluding vuln) >>= splitSemVer
      rangeStartExcluding = (_vuln_startVersionExcluding vuln) >>= splitSemVer
      rangeEndIncluding = (_vuln_endVersionIncluding vuln) >>= splitSemVer
      rangeEndExcluding = (_vuln_endVersionExcluding vuln) >>= splitSemVer
      m = [ liftM2 (<=) rangeStartIncluding localver
          , liftM2 (<) rangeStartExcluding localver
          , liftM2 (<=) localver rangeEndIncluding
          , liftM2 (<) localver rangeEndExcluding
          ]
  in
      (and $ catMaybes m) && (or $ map isJust m)

match :: SBOM -> [SBOMVulnerability] -> Parameters -> IO ()
match inventory knownVulnerabilities params = do
    case _sbom_components inventory of
      Nothing -> putStrLn "No known components?"
      Just s -> do
          let d = filter (\(InventoryComponent pname _ _) -> not $ (isJust $ T.stripSuffix ".config" pname) || (isJust $ T.stripSuffix ".service" pname)) $ getComponents s
          withApp params $ timeLog $ Named (__FILE__ <> ":" <> (tshow (__LINE__ :: Integer))) $ do
                when (debug params) $ logDebug $ pretty $ "Known deps: " <> (show $ length d)
                nvdCVEs <- timeLog $ Named (__FILE__ <> ":" <> (tshow (__LINE__ :: Integer))) $ loadNVDCVEs
                advisories <- convertToLocal nvdCVEs
                (_, matches) <- timeLog $ Named (__FILE__ <> ":" <> (tshow (__LINE__ :: Integer))) $ foldM (performMatching (asLookup advisories)) ([], []) d
                matchesWithStatus <- timeLog $ Named (__FILE__ <> ":" <> (tshow (__LINE__ :: Integer)))$ getStatuses matches
                let knownFalsePositives = mapMaybe _sbomvuln_id $ filter (\k -> (_sbomvuln_analysis k >>= _sbomanalysis_state) == Just (T.pack "false_positive")) knownVulnerabilities
                let filtered = flip filter matchesWithStatus (\(match', status) -> status /= Just "notforus" && not (elem (_match_advisory_id match') knownFalsePositives))
                flip mapM_ filtered $ \(match', status) -> do
                    liftIO $ putStrLn ""
                    logWarning $ pretty $ T.unpack $ _match_name match'
                    logWarning $ pretty $ T.unpack $ _match_advisory_id match'
                    logWarning $ pretty $ "https://cve.org/CVERecord?id=" <> (T.unpack $ _match_advisory_id match')
                    case (_match_severity match') of
                      Just s' -> logWarning $ pretty $ "Severity: " <> (T.unpack s')
                      Nothing -> pure ()
                    case status of
                      Just s' -> logWarning $ pretty $ "Status: " <> (T.unpack s')
                      Nothing -> pure ()
                    case (_match_version match') of
                      Just version -> logWarning $ pretty $ "Version: " <> (T.unpack version)
                      Nothing -> pure ()
                    logWarning $ pretty $ "Full drv path: " <> (T.unpack $ _match_drv_path match')
                    liftIO $ putStrLn ""

                when (debug params) $ case (filter (\fp -> not $ elem fp (map _match_advisory_id matches)) knownFalsePositives) of
                       [] -> pure ()
                       fn -> logDebug $ pretty $ "Possible false negatives: " <> (show fn)
                pure ()

    where
      getComponents :: [Component] -> [InventoryComponent]
      getComponents d = let drv_paths = mapMaybe _property_value $ filter (\p -> _property_name p == Just "nix:drv_path") $ concat $ mapMaybe _component_properties d
                            split :: Text -> InventoryComponent
                            split drvpath =
                                  let name = T.reverse . T.drop 4 . T.reverse . T.drop 1 . T.dropWhile (\x -> x /= '-') $ drvpath
                                      lastSegment = T.reverse . T.takeWhile (\x -> x /= '-') . T.reverse $ name
                                      version =
                                        if T.length lastSegment == 0 then Nothing
                                        else if isDigit (T.head lastSegment) then Just lastSegment
                                        else Nothing
                                      pname = case version of
                                        Nothing -> name
                                        Just n -> T.reverse . T.drop (T.length n + 1) . T.reverse $ name
                                  in
                                    (InventoryComponent pname version drvpath)
                        in map split drv_paths

      performMatching :: LogT m ann => SetMultimap.SetMultimap Text LocalVuln -> ([(Text, Maybe Text)], [Match]) -> InventoryComponent -> ReaderT Parameters m ([(Text, Maybe Text)], [Match])
      performMatching vulns (seenSoFar, matchedSoFar) (InventoryComponent pname version drv) = do
          debug' <- debug <$> ask
          case elem (pname, version) seenSoFar of
            True -> do
                when (debug') $ logDebug $ pretty $ "Already seen " <> T.unpack pname <> " " <> maybe "" id (T.unpack <$> version)
                pure (seenSoFar, matchedSoFar)
            False -> timeLog $ Named (__FILE__ <> ":" <> (tshow (__LINE__ :: Integer))) $ do
              when (debug') $ logDebug $ pretty $ "Matching " <> T.unpack pname <> " " <> maybe "" id (T.unpack <$> version)
              let vulns' = filter (versionInRange version) (Set.toList $ SetMultimap.lookup pname vulns)
              let matches = flip map vulns' $ \vuln -> createMatch pname version drv vuln
              pure $ (seenSoFar <> [(pname, version)], matchedSoFar <> matches)

      getStatuses :: LogT m ann => [Match] -> ReaderT Parameters m [(Match, Maybe Text)]
      getStatuses matches = do
          responses <- webAppApi $ Map.fromList $ [ ("cve", (T.intercalate "," $ map _match_advisory_id matches)) ]
          pure $ filter (\(_, y) -> y /= Just "notforus") $ map (statusByMatch responses) matches
          where
            statusByMatch :: [WebAppResponse] -> Match -> (Match, Maybe Text)
            statusByMatch [] match' = (match', Nothing)
            statusByMatch (x:xs) match' =
              if (elem (_match_advisory_id match') (_webappresponse_cve x)) then (match', Just $ _webappresponse_status x)
              else statusByMatch xs match'

      asLookup :: [[LocalVuln]] -> SetMultimap.SetMultimap Text LocalVuln
      asLookup vulns =
            SetMultimap.fromList $ mapMaybe asTuple $ concat vulns
            where
              asTuple :: LocalVuln -> Maybe (Text, LocalVuln)
              asTuple vuln = case _vuln_product vuln of
                Just v -> Just (v, vuln)
                Nothing -> Nothing
