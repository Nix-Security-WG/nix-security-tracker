-- SPDX-FileCopyrightText: 2023 Arnout Engelen <arnout@bzzt.net>
-- SPDX-FileCopyrightText: 2023 Dylan Green <dylan.green@obsidian.systems>
--
-- SPDX-License-Identifier: MIT

{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Options.Applicative

import LocalSecurityScanner.SBOM
import LocalSecurityScanner.Matching
import LocalSecurityScanner.Types
import LocalSecurityScanner.Utils
import System.Directory
import System.Process


programOptions :: Parser Parameters
programOptions = Parameters
  <$> switch (  long "debug"
             <> short 'v'
             <> help "Debug logging"
             )
  <*> strOption (  long "sbom"
                <> value "sbom.cdx.json"
                <> help "SBOM to ingest"
                <> metavar "SBOM JSON"
                <> showDefault
                )
  <*> (optional $ strOption ( long "path"
                <> help "Path to ingest"
                ))
  <*> (optional $ strOption (  long "vex"
                <> help "VEX to ingest to exclude advisories which have been verified not to affect the current context"
                <> metavar "VEX JSON"
                ))
  <*> switch (long "timeinfo")
  <*> (optional $ many (strOption (long "exclude-vendor")))
  <*> (optional $ strOption (  long "security-tracker-url"
                            <> help "Web Tracker to ingest from"
                            <> metavar "URL"
                            ))
  <*> (optional $ strOption (  long "cache-dir"
                            <> help "Directory to store cache files to"
                            <> metavar "CACHE_DIR"
                            ))

parameterInfo :: ParserInfo Parameters
parameterInfo = info (helper <*> programOptions) (fullDesc <> progDesc "Nix Security Scanner" <> header "Nix Security Scanner")


main :: IO ()
main = do
    params <- execParser parameterInfo
    case path params of
      Just drv' -> do
        callProcess (sbomnixExe) [drv']
        go params "./sbom.cdx.json"
      _ -> do
        let sbomFile = sbom params
        sbomExists <- doesFileExist $ sbomFile
        if sbomExists then go params sbomFile
        else error "Please specify drv path or sbom file to analyze"

 where
     go params sbom' = do
       sbom'' <- parseSBOM sbom'
       vex' <- case (vex params) of
           Nothing -> pure $ Just []
           Just v -> parseVEX v
       case (sbom'', vex') of
         (Nothing, _) ->
           putStrLn "[SBOM] Failed to parse"
         (_, Nothing) ->
           putStrLn "[VEX] Failed to parse"
         (Just s, Just v) ->
           match s v params
