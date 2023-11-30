{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Options.Applicative

import CVENix.SBOM
import CVENix.Examples
import CVENix.Matching
import System.Process
import System.Posix.Files

data Parameters = Parameters
  { debug :: !Bool
  , sbom :: !String
  , path :: !(Maybe String)
  } deriving (Show, Eq, Ord)

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
            callProcess "sbomnix" [drv', "--type", "runtime"]
            go params
          _ -> error "Please specify drv file"

 where
     go params = do
       let sbom' = sbom params
           debug' = debug params
       sbom'' <- parseSBOM $ sbom'
       cves <- exampleParseCVE
       case sbom'' of
         Nothing ->
           putStrLn "[SBOM] Failed to parse"
         Just s ->
           match s cves $ debug'
