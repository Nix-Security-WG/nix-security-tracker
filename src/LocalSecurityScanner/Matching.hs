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

data InventoryDependency = InventoryDependency
  { _inventorydependency_pname :: Text
  , _inventorydependency_version :: Maybe Text
  , _inventorydependency_drv :: Text
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
      rangeEndExcluding = (_vuln_endVersionExcluding vuln) >>= splitSemVer
      rangeEndIncluding = (_vuln_endVersionIncluding vuln) >>= splitSemVer
  in
      and $ catMaybes [ liftM2 before localver rangeEndExcluding
                      , liftM2 through localver rangeEndIncluding ]
  where
    before :: SemVer -> SemVer -> Bool
    before one other =
      if | _semver_major other > _semver_major one -> True
         | _semver_major other == _semver_major one && _semver_minor other > _semver_minor one -> True
         | _semver_major other == _semver_major one && _semver_minor other == _semver_minor one && _semver_patch other > _semver_patch one -> True
         | otherwise -> False
    through :: SemVer -> SemVer -> Bool
    through version rangeEnd =
      if | _semver_major rangeEnd > _semver_major version -> True
         | _semver_major rangeEnd == _semver_major version && _semver_minor rangeEnd > _semver_minor version -> True
         | _semver_major rangeEnd == _semver_major version && _semver_minor rangeEnd == _semver_minor version && _semver_patch rangeEnd >= _semver_patch version -> True
         | otherwise -> False

match :: SBOM -> Parameters -> IO ()
match inventory params = do
    case _sbom_dependencies inventory of
      Nothing -> putStrLn "No known deps?"
      Just s -> do
          let d = filter (\(InventoryDependency pname _ _) -> not $ (isJust $ T.stripSuffix ".config" pname) || (isJust $ T.stripSuffix ".service" pname)) $ getDeps s
          withApp params $ timeLog $ Named (__FILE__ <> ":" <> (tshow (__LINE__ :: Integer))) $ do
                when (debug params) $ logMessage $ WithSeverity Debug $ pretty $ "Known deps: " <> (show $ length d)
                nvdCVEs <- timeLog $ Named (__FILE__ <> ":" <> (tshow (__LINE__ :: Integer))) $ loadNVDCVEs
                advisories <- convertToLocal nvdCVEs
                (_, matches) <- timeLog $ Named (__FILE__ <> ":" <> (tshow (__LINE__ :: Integer))) $ foldM (performMatching (asLookup advisories)) ([], []) d
                matchesWithStatus <- timeLog $ Named (__FILE__ <> ":" <> (tshow (__LINE__ :: Integer)))$ getStatuses matches
                flip mapM_ matchesWithStatus $ \(match', status) -> do
                    liftIO $ putStrLn ""
                    logMessage $ WithSeverity Warning $ pretty $ T.unpack $ _match_name match'
                    logMessage $ WithSeverity Warning $ pretty $ T.unpack $ _match_advisory_id match'
                    logMessage $ WithSeverity Warning $ pretty $ "https://cve.org/CVERecord?id=" <> (T.unpack $ _match_advisory_id match')
                    case (_match_severity match') of
                      Just s' -> logMessage $ WithSeverity Warning $ pretty $ "Severity: " <> (T.unpack s')
                      Nothing -> pure ()
                    case status of
                      Just s' -> logMessage $ WithSeverity Warning $ pretty $ "Status: " <> (T.unpack s')
                      Nothing -> pure ()
                    case (_match_version match') of
                      Just version -> logMessage $ WithSeverity Warning $ pretty $ "Version: " <> (T.unpack version)
                      Nothing -> pure ()
                    logMessage $ WithSeverity Warning $ pretty $ "Full drv path: " <> (T.unpack $ _match_drv_path match')
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
            False -> timeLog $ Named (__FILE__ <> ":" <> (tshow (__LINE__ :: Integer))) $ do
              when (debug') $ logMessage $ WithSeverity Debug $ pretty $ "Matching " <> T.unpack pname <> " " <> maybe "" id (T.unpack <$> version)
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
