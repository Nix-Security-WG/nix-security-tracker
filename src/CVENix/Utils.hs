{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

module CVENix.Utils where

import Data.Aeson

stripType :: Options
stripType = defaultOptions { fieldLabelModifier = stripTypeNamePrefix }
  where
    stripTypeNamePrefix :: String -> String
    stripTypeNamePrefix = drop 1 . namingWrong . dropWhile (\x -> x /= '_') . drop 1 . namingWrong

    namingWrong :: String -> String
    namingWrong a = if head a /= '_' then error ("Naming is wrong for " <> a) else a

stripType' :: Options
stripType' = defaultOptions { fieldLabelModifier = stripTypeNamePrefix }
  where
    stripTypeNamePrefix :: String -> String
    stripTypeNamePrefix = replaceUnderScores . drop 1 . namingWrong . dropWhile (\x -> x /= '_') . drop 1 . namingWrong

    namingWrong :: String -> String
    namingWrong a = if head a /= '_' then error ("Naming is wrong for " <> a) else a

    replaceUnderScores :: String -> String
    replaceUnderScores a = flip map a $ \x -> if x == '_' then '-' else x

