-- SPDX-FileCopyrightText: 2023 Arnout Engelen <arnout@bzzt.net>
-- SPDX-FileCopyrightText: 2023 Dylan Green <dylan.green@obsidian.systems>
--
-- SPDX-License-Identifier: MIT

{-# LANGUAGE OverloadedStrings #-}
module Main where

import Debug.Trace
import Test.Hspec

import Data.Aeson
import Data.Maybe
import qualified Data.Text as T

import LocalSecurityScanner.NVD
import LocalSecurityScanner.Types
import LocalSecurityScanner.Utils
import LocalSecurityScanner.Matching

parseNVDSpec :: SpecWith (Arg (IO ()))
parseNVDSpec = do
  it "Parses a CVE from the NVD feed into our local data model" $ do
    Just nvdcve <- decodeFileStrict "tests/resources/CVE-2023-32611.json"
    advisoryParts <- withApp def $ convertToLocal [nvdcve]
    (length $ concat advisoryParts) `shouldNotBe` (0 :: Int)

versionShouldNotMatch :: String -> String -> SpecWith (Arg (IO ()))
versionShouldNotMatch version advisoryId = do
  it ("Version " <> version <> " should not match " <> advisoryId) $ do
    Just nvdcve <- decodeFileStrict $ "tests/resources/" <> advisoryId <> ".json"
    [advisory_parts] <- withApp def $ convertToLocal [nvdcve]
    flip mapM_ advisory_parts (\advisory -> (versionInRange (Just $ T.pack version) advisory) `shouldBe` False)

versionShouldMatch :: String -> String -> SpecWith (Arg (IO ()))
versionShouldMatch version advisoryId = do
  it ("Version " <> version <> " should match " <> advisoryId) $ do
    Just nvdcve <- decodeFileStrict $ "tests/resources/" <> advisoryId <> ".json"
    [advisoryParts] <- withApp def $ convertToLocal [nvdcve]
    (or $ map (\advisory -> versionInRange (Just $ T.pack version) advisory) advisoryParts) `shouldBe` True

main :: IO ()
main = hspec $ do
    describe "Parse NVD Spec" $ do
        parseNVDSpec
    describe "Match version ranges with 'versionEndExcluding'" $ do
        versionShouldMatch "2.74.1" "CVE-2023-32611"
        versionShouldNotMatch "2.74.2" "CVE-2023-32611"
        versionShouldNotMatch "2.78.1" "CVE-2023-32611"
    describe "Match version ranges with 'versionEndIncluding'" $ do
        versionShouldMatch "1.22.11" "CVE-2023-5982"
        versionShouldMatch "1.23.9" "CVE-2023-5982"
        versionShouldMatch "1.23.10" "CVE-2023-5982"
        versionShouldNotMatch "1.23.11" "CVE-2023-5982"
        versionShouldNotMatch "2.0.0" "CVE-2023-5982"
    describe "Match version ranges with 'versionStartIncluding'" $ do
        versionShouldNotMatch "3.0.12" "CVE-2023-2975"
    describe "Match version ranges with 4-segment versions" $ do
        versionShouldNotMatch "4.11.2" "CVE-2006-7246"
