{-# LANGUAGE OverloadedStrings #-}
module CVENix.Matching where

import CVENix.SBOM
import CVENix.Types
import CVENix.CVE
import Data.Maybe
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Multimap.Set as SetMultimap
import qualified Data.Text as T

match :: SBOM -> [Advisory] -> IO ()
match sbom cves = do
    putStrLn "Matched advisories:"
    case _sbom_dependencies sbom of
      Nothing -> putStrLn "No known deps?"
      Just s -> do
          let d = getDeps $ Just s
          case d of
            Nothing -> pure ()
            Just a' ->
              let
                pretty :: Match -> String
                pretty m =
                  let pname = _match_pname m
                      drv = _match_drv m
                      advisoryId = _advisory_id $ _match_advisory m
                      versionSpec = (mapMaybe _advisory_product_versions $ _advisory_products $ _match_advisory m)
                      -- TODO deduplicate somehow?
                      versions = map (\x -> VersionData (_version_version x) (maybeVuln x) (_version_status x)) <$> versionSpec
                  in show pname ++ "\t" ++ show drv ++ "\t" ++ show advisoryId <> "\n" <> show versions <> "\n"
              in
                mapM_ putStrLn $ map pretty $ matchNames a' cves

  where
      maybeVuln a = if isJust $ _version_lessThan a then
                        (\x -> "lessThan " <> x) <$> _version_lessThan a
                    else if isJust $ _version_lessThanOrEqual a then
                        (\x -> "lessThanOrEqual " <> x) <$> _version_lessThanOrEqual a
                    else
                        Just "exactly"

      getDeps a = case a of
                  Nothing -> Nothing
                  Just d -> Just $ do
                      let deps = map (_sbomdependency_ref) d
                          split :: Text -> (Text, Text, Text)
                          split path =
                            let name = T.drop 1 . T.dropWhile (\x -> x /= '-') $ path
                                -- TODO correctly handle names like 'source-highlight-3.1.9', 'xorg-server', etc
                                pname = T.takeWhile (\x -> x /= '-') name
                                -- TODO correctly handle (skip?) names that don't contain a version
                                version = T.reverse . T.drop 4 . T.takeWhile (\x -> x /= '-') . T.reverse $ name
                            in
                              (pname, version, path)
                      map split deps
      matchNames :: [(Text, Text, Text)] -> [Advisory] -> [Match]
      matchNames inventory advisories =
                  let
                    advisoriesByProductName :: SetMultimap.SetMultimap Text Advisory
                    advisoriesByProductName =
                      SetMultimap.fromList $ concat $ map (\a -> mapMaybe
                                                          (\ap -> case (_advisory_product_productName ap) of
                                                                  Just p -> Just (p, a)
                                                                  Nothing -> Nothing) $ _advisory_products a) advisories
                  in
                    concat $ map
                        (\package ->
                            let (pname, _, path) = package
                            in map (\matched_advisory -> Match pname path matched_advisory) (Set.toList $ SetMultimap.lookup pname advisoriesByProductName))
                        inventory
