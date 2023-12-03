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
          let withLoggingT f = runLoggingT (runReaderT f params) (print . renderWithSeverity id) in withLoggingT $ timeLog $ do
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
              id' = _nvdcve_id x
              versions = case configs of
                Nothing -> []
                Just cfg -> flip concatMap cfg $ \cc -> do
                    let cpeMatch = (concatMap _node_cpeMatch (_configuration_nodes cc))
                    flip concatMap cpeMatch $ \c -> do
                        let nvdVer = _cpematch_versionEndIncluding c
                            cpe = (parseCPE $ _cpematch_criteria c)
                        [LocalVuln nvdVer (_cpe_product <$> cpe) id']
          pure versions



      getFromNVD :: LogT m ann => [LocalVuln] -> [(Text, Maybe Text)] -> InventoryDependency -> ReaderT Parameters m [(Text, Maybe Text)]
      getFromNVD vulns acc (InventoryDependency pname version _drv) = do
          debug' <- debug <$> ask
          let localver = splitSemVer <$> version
          case elem (pname, version) acc of
            True -> do
                when (debug') $ logMessage $ colorize $ WithSeverity Debug $ pretty $ "Already seen " <> T.unpack pname <> " " <> maybe "" id (T.unpack <$> version)
                pure acc
            False -> timeLog $ do
              when (debug') $ logMessage $ WithSeverity Debug $ pretty $ "Matching " <> T.unpack pname <> " " <> maybe "" id (T.unpack <$> version)
              let  vulns' = flip map vulns $ \(LocalVuln endVer product cveId) -> do
                    let nvdVer = splitSemVer <$> endVer
                        nvdCPE = (\c -> pname == c) <$> (product)
                    case nvdCPE of
                      (Just True) -> case nvdVer of
                        Nothing -> Nothing
                        Just ver' -> do
                          case (ver', localver) of
                            (Just v, Just (Just lv)) -> do
                                if | _semver_major v > _semver_major lv -> Just (cveId, lv, v)
                                   | _semver_major v >= _semver_major lv && _semver_minor v >= _semver_minor lv && _semver_patch v >= _semver_patch lv -> Just (cveId, lv, v)
                                   | otherwise -> Nothing
                            (_, _) -> Nothing
                      _ -> Nothing

              timeLog $ flip mapM_ vulns' $ \case
                Nothing -> pure ()
                Just (cid, local, nvd) -> timeLog $ do
                    liftIO $ putStrLn ""
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ T.unpack pname
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ T.unpack cid
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ "Vulnerable version: " <> prettySemVer nvd
                    logMessage $ colorize $ WithSeverity Warning $ pretty $ "Local Version: " <> prettySemVer local
                    liftIO $ putStrLn ""
              pure $ acc <> [(pname, version)]







    {-match' :: SBOM -> [Advisory] -> IO ()
match' sbom cves = do
    putStrLn "Matched advisories:"
    case _sbom_dependencies sbom of
      Nothing -> putStrLn "No known deps?"
      Just s -> do
          let d = getDeps $ Just s
          case d of
            Nothing -> pure ()
            Just a' -> do
                --run <- mapM (pretty) $ filter isVersionAffected $ matchNames a' cves
                --mapM_ putStrLn run
                foldM_ (fetchFromNVD) ([] :: [Text]) $ nub $ filter isVersionAffected $ matchNames a' cves

  where

      fetchFromNVD :: [Text] -> Match -> IO [Text]
      fetchFromNVD acc m = do
          let pname = _match_pname m
          case elem pname acc of
            True -> do
              pure acc
            False -> do
              response <- keywordSearch pname
              let configs = map (\x -> (_nvdcve_id $ _nvdwrapper_cve x, _nvdcve_configurations $ _nvdwrapper_cve x)) $ _nvdresponse_vulnerabilities response
              let versions = flip map configs $ uncurry $ \cveId -> \case
                    Nothing -> ("Fail", [])
                    Just conf ->
                        (cveId, catMaybes $ map (_cpematch_versionEndIncluding) (concat (map _node_cpeMatch (concat (map _configuration_nodes conf)))))
              let vulns = flip concatMap versions $ uncurry $ \cveId x' -> flip map x' $ \x -> do
                    let nvdVer = splitSemVer x
                        matchVer = splitSemVer (_match_version m)
                    case (nvdVer, matchVer) of
                      (Nothing, Nothing) -> (matchVer, cveId, False)
                      (Just nvd, Just l) -> do
                        if _semver_major nvd >= _semver_major l && _semver_minor nvd >= _semver_minor l && nvd /= l then
                          (matchVer, cveId, True)
                        else
                          (matchVer, cveId, False)
                      _ -> (matchVer, cveId, False)
              flip mapM_ vulns $ \(x, cveId, y) -> case y of
                  True -> do
                    putStrLn $ T.unpack pname
                    print $ _match_version m
                    putStrLn $ "CVEID: " <> T.unpack cveId
                    print $ prettySemVer <$> x
                    putStrLn $ "Vulnerable!"
                  False -> do
                    putStrLn $ T.unpack pname
                    print $ _match_version m
                    putStrLn $ "CVEID: " <> T.unpack cveId
                    print $ prettySemVer <$> x
                    putStrLn $ "Not Vulnerable!"
                  _ -> pure ()
              pure $ acc <> [pname]

      pretty :: Match -> IO String
      pretty m = do
          let pname = _match_pname m
              drv = _match_drv m
              advisoryId = _advisory_id $ fst $ _match_advisory m
              versionSpec = _advisory_product_versions $ snd $ _match_advisory m
              -- TODO deduplicate if needed?
              versions = map (\x -> VersionData (_version_version x) (maybeVuln x) (_version_status x)) <$> versionSpec
          prettyVersions <- case versions of
            Nothing -> do
                putStrLn "Running"
                putStrLn $ show advisoryId
                putStrLn "Waiting 8 seconds...."
                result <- cveSearch advisoryId
                pure $ show $ _nvdresponse_totalResults result
            Just a -> pure $ show a
          pure $ show pname ++ "\t" ++ show drv ++ "\t" ++ show advisoryId <> "\n" <> show prettyVersions <> "\n"

      isVersionAffected :: Match -> Bool
      isVersionAffected match' =
        let
          product' = snd $ _match_advisory match'

          defaultStatus :: Text
          defaultStatus = maybe "unknown" id (_advisory_product_defaultStatus product')

          versions :: [Version]
          versions = maybe [] id (_advisory_product_versions product')

          matches :: Version -> Bool
          matches v =
            if _version_version v == _match_version match' then True
            -- TODO take into account 'lessThan'/'lessThanOrEqual' if present
            else False

          getStatus :: [Version] -> Text
          getStatus [] = defaultStatus
          getStatus (v:vs) =
            if (matches v)
              then _version_status v
              else getStatus vs
        in getStatus versions == "affected"

      maybeVuln a = if isJust $ _version_lessThan a then
                        LessThan <$> _version_lessThan a
                    else if isJust $ _version_lessThanOrEqual a then
                        LessThanOrEqual <$> _version_lessThanOrEqual a
                    else Just Exact

      getDeps a = case a of
                  Nothing -> Nothing
                  Just d -> Just $ do
                      let deps = map (_sbomdependency_ref) d
                          split :: Text -> (Text, Maybe Text, Text)
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
                              (pname, version, path)
                      map split deps

      matchNames :: [(Text, Maybe Text, Text)] -> [Advisory] -> [Match]
      matchNames inventory advisories =
                  let
                    advisoriesByProductName :: SetMultimap Text (Advisory, AdvisoryProduct)
                    advisoriesByProductName =
                      SetMultimap.fromList $ concat $ map (\a -> mapMaybe
                                                          (\ap -> case (_advisory_product_productName ap) of
                                                                  Just p -> Just (p, (a, ap))
                                                                  Nothing -> Nothing) $ _advisory_products a) advisories
                  in
                    concatMap
                        (\package ->
                            let (pname, version, path) = package
                            in
                              case version of
                                Nothing -> []
                                Just v -> map (\matched_advisory -> Match pname v path matched_advisory) (Set.toList $ SetMultimap.lookup pname advisoriesByProductName)
                        )
                        inventory-}
