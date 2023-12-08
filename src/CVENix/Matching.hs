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

import Data.Maybe
import Data.Char (isDigit)
import Data.Text (Text)
import qualified Data.Text as T
import Control.Monad
import Control.Monad.Log
import Control.Monad.Log.Colors
import Control.Monad.IO.Class
import Prettyprinter
import Control.Monad.Trans.Reader

data InventoryDependency = InventoryDependency
  { _inventorydependency_pname :: Text
  , _inventorydependency_version :: Maybe Text
  , _inventorydependency_drv :: Text
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
                     | _semver_major v >= _semver_major lv && _semver_minor v >= _semver_minor lv && _semver_patch v >= _semver_patch lv -> Just (advisoryId, severity, lv, v)
                     | otherwise -> Nothing
              (_, _) -> Nothing

match :: SBOM -> Parameters -> IO ()
match inventory params = do
    putStrLn "Matched advisories:"
    case _sbom_dependencies inventory of
      Nothing -> putStrLn "No known deps?"
      Just s -> do
          let d = filter (\(InventoryDependency pname _ _) -> not $ (isJust $ T.stripSuffix ".config" pname) || (isJust $ T.stripSuffix ".service" pname)) $ getDeps s
          withApp params $ timeLog $ do
                when (debug params) $ logMessage $ WithSeverity Debug $ pretty $ "Known deps: " <> (show $ length d)
                nvdCVEs <- timeLog $ loadNVDCVEs
                matches <- convertToLocal nvdCVEs
                timeLog $ foldM_ (getFromNVD (concat matches)) ([] :: [(Text, Maybe Text)]) d

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

      getFromNVD :: LogT m ann => [LocalVuln] -> [(Text, Maybe Text)] -> InventoryDependency -> ReaderT Parameters m [(Text, Maybe Text)]
      getFromNVD vulns acc (InventoryDependency pname version drv) = do
          debug' <- debug <$> ask
          case elem (pname, version) acc of
            True -> do
                when (debug') $ logMessage $ colorize $ WithSeverity Debug $ pretty $ "Already seen " <> T.unpack pname <> " " <> maybe "" id (T.unpack <$> version)
                pure acc
            False -> timeLog $ do
              when (debug') $ logMessage $ WithSeverity Debug $ pretty $ "Matching " <> T.unpack pname <> " " <> maybe "" id (T.unpack <$> version)
              let  vulns' = flip map vulns $ \vuln -> do
                    case (_vuln_product vuln) of
                      (Just name) ->
                        if name == pname then versionInRange vuln version else Nothing
                      _ -> Nothing

              timeLog $ flip mapM_ vulns' $ \case
                Nothing -> pure ()
                Just (cid, severity, version, rangeEnd) -> timeLog $ do
                    liftIO $ putStrLn ""
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ T.unpack pname
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ T.unpack cid
                    case severity of
                      Just s -> logMessage $ colorize $ WithSeverity Warning $ pretty $ T.unpack s
                      Nothing -> pure ()
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ "Vulnerable version range end: " <> prettySemVer rangeEnd
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ "Local Version: " <> prettySemVer version
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ "Full drv path: " <> T.unpack drv
                    liftIO $ putStrLn ""
              pure $ acc <> [(pname, version)]
