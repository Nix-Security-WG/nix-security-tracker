{-# LANGUAGE OverloadedStrings #-}
module Main where

import Debug.Trace
import Test.Hspec

import Data.Aeson
import Data.Maybe
import qualified Data.Text as T

import CVENix.NVD
import CVENix.Types
import CVENix.Utils
import CVENix.Matching

parseNVDSpec :: Parameters -> SpecWith (Arg (IO ()))
parseNVDSpec params = do
  it "needs to parse a CVE from the NVD feed into our local data model" $ do
    Just nvdcve <- decodeFileStrict "tests/resources/CVE-2023-32611.json"
    advisoryParts <- withApp params $ convertToLocal [nvdcve]
    (length $ concat advisoryParts) `shouldNotBe` (0 :: Int)

versionShouldNotMatch :: Parameters -> String -> String -> SpecWith (Arg (IO ()))
versionShouldNotMatch params version advisoryId = do
  it ("version " <> version <> " should not match " <> advisoryId) $ do
    Just nvdcve <- decodeFileStrict $ "tests/resources/" <> advisoryId <> ".json"
    [[advisory]] <- withApp params $ convertToLocal [nvdcve]
    (versionInRange advisory (Just $ T.pack version)) `shouldBe` Nothing

versionShouldMatch :: Parameters -> String -> String -> SpecWith (Arg (IO ()))
versionShouldMatch params version advisoryId = do
  it ("version " <> version <> " should match " <> advisoryId) $ do
    Just nvdcve <- decodeFileStrict $ "tests/resources/" <> advisoryId <> ".json"
    [[advisory]] <- withApp params $ convertToLocal [nvdcve]
    (versionInRange advisory (Just $ T.pack version)) `shouldSatisfy` isJust

main :: IO ()
main = hspec $ do
    let params = Parameters False "test.sbom" (Just "/nix/store/test") False
    describe "Parse NVD Spec" $ do
        parseNVDSpec params
        -- TODO fix implementation
        --versionShouldMatch params "2.74.2" "CVE-2023-32611"
        versionShouldNotMatch params "2.74.3" "CVE-2023-32611"
        versionShouldNotMatch params "2.78.1" "CVE-2023-32611"
