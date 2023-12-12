{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE FlexibleContexts #-}
module CVENix.Matching where

import CVENix.SBOM
import CVENix.Types
import CVENix.NVD
import CVENix.Utils
import CVENix.WebData

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

data InventoryDependency = InventoryDependency
  { _inventorydependency_pname :: Text
  , _inventorydependency_version :: Maybe Text
  , _inventorydependency_drv :: Text
  } deriving (Show)

data Match = Match
  { _match_name :: Text
  , _match_advisory_id :: Text
  , _match_severity :: Maybe Text
  , _match_advisory_range_end :: SemVer
  , _match_matched_version :: SemVer
  , _match_drv_path :: Text
  } deriving (Show)

versionInRange :: LocalVuln -> Maybe Text -> Maybe (Text, Maybe Text, SemVer, SemVer)
versionInRange vuln version =
  let advisoryId = _vuln_cveId vuln
      localver = splitSemVer <$> version
      rangeEndIncluding = splitSemVer <$> (_vuln_endVersionIncluding vuln)
      rangeEndExcluding = splitSemVer <$> (_vuln_endVersionExcluding vuln)
      severity = _vuln_severity vuln
  in case rangeEndIncluding of
      Nothing -> case rangeEndExcluding of
          Nothing -> Nothing
          Just ver' -> do
              case (ver', localver) of
                  (Just v, Just (Just lv)) -> do
                      if | _semver_major v > _semver_major lv -> Just (advisoryId, severity, lv, v)
                         | _semver_major v == _semver_major lv && _semver_minor v > _semver_minor lv -> Just (advisoryId, severity, lv, v)
                         | _semver_major v == _semver_major lv && _semver_minor v == _semver_minor lv && _semver_patch v > _semver_patch lv -> Just (advisoryId, severity, lv, v)
                         | otherwise -> Nothing
                  (_, _) -> Nothing
      Just ver' -> do
          case (ver', localver) of
              (Just v, Just (Just lv)) -> do
                  if | _semver_major v > _semver_major lv -> Just (advisoryId, severity, lv, v)
                     | _semver_major v == _semver_major lv && _semver_minor v > _semver_minor lv -> Just (advisoryId, severity, lv, v)
                     | _semver_major v == _semver_major lv && _semver_minor v == _semver_minor lv && _semver_patch v >= _semver_patch lv -> Just (advisoryId, severity, lv, v)
                     | otherwise -> Nothing
              (_, _) -> Nothing

match :: SBOM -> Parameters -> IO ()
match inventory params = do
    case _sbom_dependencies inventory of
      Nothing -> putStrLn "No known deps?"
      Just s -> do
          let d = filter (\(InventoryDependency pname _ _) -> not $ (isJust $ T.stripSuffix ".config" pname) || (isJust $ T.stripSuffix ".service" pname)) $ getDeps s
          withApp params $ timeLog $ do
                when (debug params) $ logMessage $ WithSeverity Debug $ pretty $ "Known deps: " <> (show $ length d)
                nvdCVEs <- timeLog $ loadNVDCVEs
                advisories <- convertToLocal nvdCVEs
                (_, matches) <- timeLog $ foldM (performMatching (asLookup advisories)) ([], []) d
                matchesWithStatus <- timeLog $ getStatuses matches
                flip mapM_ matchesWithStatus $ \(match, status) -> do
                    liftIO $ putStrLn ""
                    logMessage $ WithSeverity Warning $ pretty $ T.unpack $ _match_name match
                    logMessage $ WithSeverity Warning $ pretty $ T.unpack $ _match_advisory_id match
                    case (_match_severity match) of
                      Just s -> logMessage $ WithSeverity Warning $ pretty $ "Severity: " <> (T.unpack s)
                      Nothing -> pure ()
                    case status of
                      Just s -> logMessage $ WithSeverity Warning $ pretty $ "Status: " <> (T.unpack s)
                      Nothing -> pure ()
                    logMessage $ WithSeverity Warning $ pretty $ "Vulnerable version range end: " <> (prettySemVer $ _match_advisory_range_end match)
                    logMessage $ WithSeverity Warning $ pretty $ "Version in inventory: " <> (prettySemVer $ _match_matched_version match)
                    logMessage $ WithSeverity Warning $ pretty $ "Full drv path: " <> (T.unpack $ _match_drv_path match)
                    liftIO $ putStrLn ""

                pure ()

    where
      getDeps :: [SBOMDependency] -> [InventoryDependency]
      getDeps d = let deps = map (_sbomdependency_ref) d
                      split :: Text -> InventoryDependency
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
                              (InventoryDependency pname version drvpath)
                  in map split deps

      performMatching :: LogT m ann => SetMultimap.SetMultimap Text LocalVuln -> ([(Text, Maybe Text)], [Match]) -> InventoryDependency -> ReaderT Parameters m ([(Text, Maybe Text)], [Match])
      performMatching vulns (seenSoFar, matchedSoFar) (InventoryDependency pname version drv) = do
          debug' <- debug <$> ask
          case elem (pname, version) seenSoFar of
            True -> do
                when (debug') $ logMessage $ WithSeverity Debug $ pretty $ "Already seen " <> T.unpack pname <> " " <> maybe "" id (T.unpack <$> version)
                pure (seenSoFar, matchedSoFar)
            False -> timeLog $ do
              when (debug') $ logMessage $ WithSeverity Debug $ pretty $ "Matching " <> T.unpack pname <> " " <> maybe "" id (T.unpack <$> version)
              let vulns' = flip mapMaybe (Set.toList $ SetMultimap.lookup pname vulns) $ \vuln -> versionInRange vuln version
              let matches = flip map vulns' $ \(cid, severity, v, rangeEnd) -> Match pname cid severity rangeEnd v drv
              pure $ (seenSoFar <> [(pname, version)], matchedSoFar <> matches)

      getStatuses :: LogT m ann => [Match] -> ReaderT Parameters m [(Match, Maybe Text)]
      getStatuses matches = do
          responses <- webAppApi $ Map.fromList $ map (\m -> ("cve", _match_advisory_id m)) matches
          pure $ map (statusByMatch responses) matches
          where
            statusByMatch :: [WebAppResponse] -> Match -> (Match, Maybe Text)
            statusByMatch [] match = (match, Nothing)
            statusByMatch (x:xs) match =
              if (elem (_match_advisory_id match) (_webappresponse_cve x)) then (match, Just $ _webappresponse_status x)
              else statusByMatch xs match

      asLookup :: [[LocalVuln]] -> SetMultimap.SetMultimap Text LocalVuln
      asLookup vulns =
            SetMultimap.fromList $ mapMaybe asTuple $ concat vulns
            where
              asTuple :: LocalVuln -> Maybe (Text, LocalVuln)
              asTuple vuln = case _vuln_product vuln of
                Just v -> Just (v, vuln)
                Nothing -> Nothing
