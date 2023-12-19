-- SPDX-FileCopyrightText: 2023 Arnout Engelen <arnout@bzzt.net>
-- SPDX-FileCopyrightText: 2023 Dylan Green <dylan.green@obsidian.systems>
--
-- SPDX-License-Identifier: MIT

{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module LocalSecurityScanner.Examples where

import Data.Aeson
import LocalSecurityScanner.CVE
import System.Directory
import Data.Time.Clock

exampleParseCVE :: IO [CVE]
exampleParseCVE = do
    files' <- listDirectory "CVE/cves/"
    let files = filter (\x -> not (x == "delta.json" || x == "deltaLog.json")) files'
    thing <- flip mapM files $ \version -> do
        let prefix = "CVE/cves/" <> version <> "/"
        dir <- listDirectory prefix
        flip mapM dir $ \group -> do
          let prefix' = prefix <> group <> "/"
          dir' <- listDirectory prefix'
          flip mapM dir' $ \x -> do
            pure $ prefix' <> x
    let thing' = concat $ concat thing
    print $ length thing'
    putStrLn $ "[CVE] Parsing " <> (show $ length thing') <> " files"
    curTime <- getCurrentTime
    l <- flip mapM thing' $ \x -> do
      file <- decodeFileStrict x :: IO (Maybe CVE)
      case file of
        Just cve -> pure cve
        Nothing -> fail $ "Failed to parse " <> x
    putStrLn $ "[CVE] Done parsing"
    curTime' <- getCurrentTime
    putStrLn $ "[CVE] Time to run: " <> (show $ diffUTCTime curTime curTime' * (-1))
    pure $ l
