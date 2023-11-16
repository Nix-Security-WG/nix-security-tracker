module Main where

import System.Environment
import CVENix.CVE
import CVENix.SBOM

printInventory :: [Component] -> IO ()
printInventory components = putStrLn $ "[main] Parsed inventory, found " <> (show $ length components) <> " components"
notParsed :: IO ()
notParsed = putStrLn "SBOM parsing failed"

main :: IO ()
main = do
    args <- getArgs
    sbom <- parseSbom $ head args
    maybe notParsed printInventory $ sbom >>= _sbom_components
    exampleParse
