{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Options.Applicative

import CVENix.SBOM
import CVENix.Matching
import CVENix.Types
import System.Directory
import System.Process
import CVENix.Utils


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
  <*> switch (long "timeinfo")
  <*> (optional $ many (strOption (long "exclude-vendor")))
  <*> (optional $ strOption (  long "security-tracker-url"
                            <> help "Web Tracker to ingest from"
                            <> metavar "URL"
                            )
      )

parameterInfo :: ParserInfo Parameters
parameterInfo = info (helper <*> programOptions) (fullDesc <> progDesc "Nix Security Scanner" <> header "Nix Security Scanner")


main :: IO ()
main = do
    params <- execParser parameterInfo
    case path params of
      Just drv' -> do
        callProcess (sbomnixExe) [drv', "--type", "runtime"]
        go params "./sbom.cdx.json"
      _ -> do
        let sbomFile = sbom params
        sbomExists <- doesFileExist $ sbomFile
        if sbomExists then go params sbomFile
        else error "Please specify drv path or sbom file to analyze"

 where
     go params sbom' = do
       sbom'' <- parseSBOM $ sbom'
       case sbom'' of
         Nothing ->
           putStrLn "[SBOM] Failed to parse"
         Just s ->
           match s params
