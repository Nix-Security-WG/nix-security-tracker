{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Options.Applicative

import CVENix.SBOM
import CVENix.Matching
import CVENix.Types
import System.Process
import System.Posix.Files
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

parameterInfo :: ParserInfo Parameters
parameterInfo = info (helper <*> programOptions) (fullDesc <> progDesc "Nix Security Scanner" <> header "Nix Security Scanner")


main :: IO ()
main = do
    params <- execParser parameterInfo
    exists <- fileExist (sbom params)
    case exists of
      True -> go params
      False -> case (path params) of
          Just drv' -> do
            callProcess (sbomnixExe) [drv', "--type", "runtime"]
            go params
          _ -> error "Please specify drv file"

 where
     go params = do
       let sbom' = sbom params
       sbom'' <- parseSBOM $ sbom'
       case sbom'' of
         Nothing ->
           putStrLn "[SBOM] Failed to parse"
         Just s ->
           match s params
