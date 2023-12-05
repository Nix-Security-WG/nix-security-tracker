{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE FlexibleContexts #-}
module CVENix.Matching where

import CVENix.SBOM
import CVENix.Types
import CVENix.CVE
import CVENix.NVD
import CVENix.Utils

import Data.Maybe
import Data.Char (isDigit)
import Data.Text (Text)
import qualified Data.Text as T
import Control.Monad
import System.Posix.Files
import Control.Monad.Log
import Control.Monad.Log.Colors
import Control.Monad.IO.Class
import Prettyprinter
import Control.Monad.Trans.Reader
import Data.Time.Clock
import qualified Data.Map.Strict as Map
import Data.Map (Map)

data InventoryDependency = InventoryDependency
  { _inventorydependency_pname :: Text
  , _inventorydependency_version :: Maybe Text
  , _inventorydependency_drv :: Text
  } deriving (Show)

match :: SBOM -> [Advisory] -> Parameters -> IO ()
match sbom _cves params = do
    putStrLn "Matched advisories:"
    case _sbom_dependencies sbom of
      Nothing -> putStrLn "No known deps?"
      Just s -> do
          let d = filter (\(InventoryDependency pname _ _) -> not $ (isJust $ T.stripSuffix ".config" pname) || (isJust $ T.stripSuffix ".service" pname)) $ getDeps s
          withApp params $ timeLog $ do
                when (debug params) $ logMessage $ WithSeverity Debug $ pretty $ "Known deps: " <> (show $ length d)
                nvdCVEs <- timeLog $ loadNVDCVEs
                matches <- matchNVD nvdCVEs
                timeLog $ foldM_ (getFromNVD (concat matches)) ([] :: [(Text, Maybe Text)]) d

    where
      getDeps :: [SBOMDependency] -> [InventoryDependency]
      getDeps d = let deps = map (_sbomdependency_ref) d
                      split :: Text -> InventoryDependency
                      split path =
                            let name = T.reverse . T.drop 4 . T.reverse . T.drop 1 . T.dropWhile (\x -> x /= '-') $ path
                                lastSegment = T.reverse . T.takeWhile (\x -> x /= '-') . T.reverse $ name
                                version =
                                  if T.length lastSegment == 0 then Nothing
                                  else if isDigit (T.head lastSegment) then Just lastSegment
                                  else Nothing
                                pname = case version of
                                  Nothing -> name
                                  Just n -> T.reverse . T.drop (T.length n + 1) . T.reverse $ name
                            in
                              (InventoryDependency pname version path)
                  in map split deps

      matchNVD :: LogT m ann => [NVDCVE] -> ReaderT Parameters m [[LocalVuln]]
      matchNVD nvds = timeLog $ flip mapM nvds $ \x -> do
          let configs = _nvdcve_configurations x
              -- TODO support for multiple or non-cvss-v31 severities
              (severity :: Maybe Text) = fmap _cvss31data_baseSeverity $ fmap _cvss31metric_cvssData $ (_nvdcve_metrics x) >>= _metric_cvssMetricV31 >>= listToMaybe
              id' = _nvdcve_id x
              versions = case configs of
                Nothing -> []
                Just cfg -> flip concatMap cfg $ \cc -> do
                    let cpeMatch = (concatMap _node_cpeMatch (_configuration_nodes cc))
                    flip concatMap cpeMatch $ \c -> do
                        let nvdVer = _cpematch_versionEndIncluding c
                            cpe = (parseCPE $ _cpematch_criteria c)
                        [LocalVuln nvdVer (_cpe_product <$> cpe) id' severity]
          pure versions



      getFromNVD :: LogT m ann => [LocalVuln] -> [(Text, Maybe Text)] -> InventoryDependency -> ReaderT Parameters m [(Text, Maybe Text)]
      getFromNVD vulns acc (InventoryDependency pname version drv) = do
          debug' <- debug <$> ask
          let localver = splitSemVer <$> version
          case elem (pname, version) acc of
            True -> do
                when (debug') $ logMessage $ colorize $ WithSeverity Debug $ pretty $ "Already seen " <> T.unpack pname <> " " <> maybe "" id (T.unpack <$> version)
                pure acc
            False -> timeLog $ do
              when (debug') $ logMessage $ WithSeverity Debug $ pretty $ "Matching " <> T.unpack pname <> " " <> maybe "" id (T.unpack <$> version)
              let  vulns' = flip map vulns $ \(LocalVuln endVer product cveId severity) -> do
                    let nvdVer = splitSemVer <$> endVer
                        nvdCPE = (\c -> pname == c) <$> (product)
                    case nvdCPE of
                      (Just True) -> case nvdVer of
                        Nothing -> Nothing
                        Just ver' -> do
                          case (ver', localver) of
                            (Just v, Just (Just lv)) -> do
                                if | _semver_major v > _semver_major lv -> Just (cveId, severity, lv, v)
                                   | _semver_major v >= _semver_major lv && _semver_minor v >= _semver_minor lv && _semver_patch v >= _semver_patch lv -> Just (cveId, severity, lv, v)
                                   | otherwise -> Nothing
                            (_, _) -> Nothing
                      _ -> Nothing

              timeLog $ flip mapM_ vulns' $ \case
                Nothing -> pure ()
                Just (cid, severity, local, nvd) -> timeLog $ do
                    liftIO $ putStrLn ""
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ T.unpack pname
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ T.unpack cid
                    case severity of
                      Just s -> logMessage $ colorize $ WithSeverity Warning $ pretty $ T.unpack s
                      Nothing -> pure ()
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ "Vulnerable version: " <> prettySemVer nvd
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ "Local Version: " <> prettySemVer local
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ "Full drv path: " <> T.unpack drv
                    liftIO $ putStrLn ""
              pure $ acc <> [(pname, version)]
