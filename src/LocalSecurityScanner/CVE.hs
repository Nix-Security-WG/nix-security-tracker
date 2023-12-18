-- SPDX-FileCopyrightText: 2023 Arnout Engelen <arnout@bzzt.net>
-- SPDX-FileCopyrightText: 2023 Dylan Green <dylan.green@obsidian.systems>
--
-- SPDX-License-Identifier: MIT

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}


module LocalSecurityScanner.CVE where

import LocalSecurityScanner.Utils

import Data.Aeson.TH
import Data.Aeson
import Data.Text (Text)
import GHC.Generics (Generic)
import qualified Data.Text as T

data CVE = CVE
  { _cve_dataType :: Text
  , _cve_dataVersion :: Text
  , _cve_cveMetadata :: CVEMetadata
  , _cve_containers :: Container
  } deriving (Show, Eq, Ord, Generic)

data CVEMetadata = CVEMetadata
  { _cvemetadata_cveId :: Text
  , _cvemetadata_assignerOrgId :: Text
  , _cvemetadata_assignerShortName :: Maybe Text
  , _cvemetadata_requesterUserId :: Maybe Text
  , _cvemetadata_serial :: Maybe Int
  , _cvemetadata_dateReserved :: Maybe Text
  , _cvemetadata_datePublished :: Maybe Text
  , _cvemetadata_dateRejected :: Maybe Text
  , _cvemetadata_dateUpdated :: Maybe Text
  , _cvemetadata_state :: Maybe Text
  } deriving (Show, Eq, Ord, Generic)


data Container = Container
  { _container_cna :: CNA
  , _container_adp :: Maybe ADP
  } deriving (Show, Eq, Ord, Generic)

data CNA = CNA
  { _cna_providerMetadata :: ProviderMetadata
  , _cna_dateAssigned :: Maybe Text
  , _cna_datePublic :: Maybe Text
  , _cna_title :: Maybe Text
  , _cna_descriptions :: Maybe [Description]
  , _cna_affected :: Maybe [Product]
  , _cna_problemTypes :: Maybe [ProblemType]
  , _cna_references :: Maybe [Reference]
  , _cna_impacts :: Maybe [Impact]
  , _cna_metrics :: Maybe [Metric]
  , _cna_configurations :: Maybe [Description]
  , _cna_workarounds :: Maybe [Description]
  , _cna_solutions :: Maybe [Description]
  , _cna_exploits :: Maybe [Description]
  , _cna_timeline :: Maybe [TimeLine]
  , _cna_credits :: Maybe [Credit]
  , _cna_source :: Maybe Object
  , _cna_tags :: Maybe [Object]
  , _cna_taxonomyMappings :: Maybe [TaxonomyMapping]
  , _cna_rejectedReasons :: Maybe [Description]
  } deriving (Show, Eq, Ord, Generic)

data ADP = ADP
  { _adp_providerMetadata :: ProviderMetadata
  , _adp_dateAssigned :: Maybe Text
  , _adp_datePublic :: Maybe Text
  , _adp_title :: Maybe Text
  , _adp_descriptions :: [Description]
  , _adp_affected :: [Product]
  , _adp_problemTypes :: Maybe [ProblemType]
  , _adp_references :: [Reference]
  , _adp_impacts :: Maybe [Impact]
  , _adp_metrics :: Maybe [Metric]
  , _adp_configurations :: Maybe [Description]
  , _adp_workarounds :: Maybe [Description]
  , _adp_solutions :: Maybe [Description]
  , _adp_exploits :: Maybe [Description]
  , _adp_timeline :: Maybe [TimeLine]
  , _adp_credits :: Maybe [Credit]
  , _adp_source :: Maybe Object
  , _adp_tags :: Maybe [Object]
  , _adp_taxonomyMappings :: Maybe [TaxonomyMapping]
  } deriving (Show, Eq, Ord, Generic)

data ProgramRoutine = ProgramRoutine
  { _programroutine_name :: Text } deriving (Show, Eq, Ord, Generic)

data ProviderMetadata = ProviderMetadata
  { _providermetadata_orgId :: Text
  , _providermetadata_shortName :: Maybe Text
  , _providermetadata_dateUpdated :: Maybe Text
  } deriving (Show, Eq, Ord, Generic)

data Description = Description
  { _description_lang :: Text
  , _description_value :: Text
  , _description_supportingMedia :: Maybe [Object]
  } deriving (Show, Eq, Ord, Generic)

data SupportingMedia = SupportingMedia
  { _supportingmedia_type :: Text
  , _supportingmedia_base64 :: Bool
  , _supportingmedia_value :: Text
  } deriving (Show, Eq, Ord, Generic)


data Product = Product
  { _product_vendor :: Maybe Text
  , _product_product :: Maybe Text
  , _product_collectionURL :: Maybe Text
  , _product_packageName :: Maybe Text
  , _product_cpes :: Maybe [Text]
  , _product_modules :: Maybe [Text]
  , _product_programFiles :: Maybe [Text]
  , _product_programRoutines :: Maybe [ProgramRoutine]
  , _product_platforms :: Maybe [Text]
  , _product_repo :: Maybe Text
  , _product_defaultStatus :: Maybe Text
  , _product_versions :: Maybe [Version]
  } deriving (Show, Eq, Ord, Generic)

data Version = Version
  { _version_version :: Text
  , _version_status :: Text
  , _version_type :: Maybe Text
  , _version_lessThan :: Maybe Text
  , _version_lessThanOrEqual :: Maybe Text
  , _version_changes :: Maybe [Change]
  } deriving (Show, Eq, Ord, Generic)

data Change = Change
  { _change_at :: Text
  , _change_status :: Text
  } deriving (Show, Eq, Ord, Generic)



type Affected = Product

data ProblemType = ProblemType { _problemtype_descriptions :: [ProblemDescription] } deriving (Show, Eq, Ord, Generic)
data ProblemDescription = ProblemDescription
  { _problemdescription_lang :: Text
  , _problemdescription_description :: Text
  , _problemdescription_cweId :: Maybe Text
  , _problemdescription_type :: Maybe Text
  , _problemdescription_references :: Maybe [Reference]
  } deriving (Show, Eq, Ord, Generic)

data Reference = Reference
  { _reference_url :: Text
  , _reference_name :: Maybe Text
  , _reference_tags :: Maybe [Text]
  } deriving (Show, Eq, Ord, Generic)

data Impact = Impact
  { _impact_capecid :: Maybe Text
  , _impact_descriptions :: [Description]
  } deriving (Show, Eq, Ord, Generic)

data Metric = Metric
  { _metric_format :: Maybe Text
  , _metric_scenarios :: Maybe [Scenario]
  , _metric_cvssV3_1 :: Maybe CVSS31
  , _metric_cvssV3_0 :: Maybe CVSS30
  , _metric_cvssV2_0 :: Maybe Object
  , _metric_other :: Maybe Object
  } deriving (Show, Eq, Ord, Generic)

data Scenario = Scenario
  { _scenario_lang :: Text
  , _scenario_value :: Text
  } deriving (Show, Eq, Ord, Generic)

data CVSS31 = CVSS31
    { _cvss31_version :: Text
    , _cvss31_vectorString :: Text
    , _cvss31_attackVector :: Maybe Text
    , _cvss31_attackComplexity :: Maybe Text
    , _cvss31_privilegesRequired :: Maybe Text
    , _cvss31_userInteraction :: Maybe Text
    , _cvss31_scope :: Maybe Text
    , _cvss31_confidentialityImpact :: Maybe Text
    , _cvss31_integrityImpact :: Maybe Text
    , _cvss31_availabilityImpact :: Maybe Text
    , _cvss31_baseScore :: Double
    , _cvss31_baseSeverity :: Text
    , _cvss31_exploitCodeMaturity :: Maybe Text
    , _cvss31_remediationLevel :: Maybe Text
    , _cvss31_reportConfidence :: Maybe Text
    , _cvss31_temporalScore :: Maybe Text
    , _cvss31_temporalSeverity :: Maybe Text
    , _cvss31_confidentialityRequirement :: Maybe Text
    , _cvss31_integrityRequirement :: Maybe Text
    , _cvss31_availabilityRequirement :: Maybe Text
    , _cvss31_modifiedAttackVector :: Maybe Text
    , _cvss31_modifiedAttackComplexity :: Maybe Text
    , _cvss31_modifiedPrivilegesRequired :: Maybe Text
    , _cvss31_modifiedUserInteraction :: Maybe Text
    , _cvss31_modifiedScope :: Maybe Text
    , _cvss31_modifiedConfidentialityImpact :: Maybe Text
    , _cvss31_modifiedIntegrityImpact :: Maybe Text
    , _cvss31_modifiedAvailabilityImpact :: Maybe Text
    , _cvss31_environmentalScore :: Maybe Text
    , _cvss31_environmentalSeverity :: Maybe Text
    } deriving (Show, Eq, Ord, Generic)

data CVSS30 = CVSS30
    { _cvss30_version :: Text
    , _cvss30_vectorString :: Text
    , _cvss30_attackVector :: Maybe Text
    , _cvss30_attackComplexity :: Maybe Text
    , _cvss30_privilegesRequired :: Maybe Text
    , _cvss30_userInteraction :: Maybe Text
    , _cvss30_scope :: Maybe Text
    , _cvss30_confidentialityImpact :: Maybe Text
    , _cvss30_integrityImpact :: Maybe Text
    , _cvss30_availabilityImpact :: Maybe Text
    , _cvss30_baseScore :: Double
    , _cvss30_baseSeverity :: Text
    , _cvss30_exploitCodeMaturity :: Maybe Text
    , _cvss30_remediationLevel :: Maybe Text
    , _cvss30_reportConfidence :: Maybe Text
    , _cvss30_temporalScore :: Maybe Text
    , _cvss30_temporalSeverity :: Maybe Text
    , _cvss30_confidentialityRequirement :: Maybe Text
    , _cvss30_integrityRequirement :: Maybe Text
    , _cvss30_availabilityRequirement :: Maybe Text
    , _cvss30_modifiedAttackVector :: Maybe Text
    , _cvss30_modifiedAttackComplexity :: Maybe Text
    , _cvss30_modifiedPrivilegesRequired :: Maybe Text
    , _cvss30_modifiedUserInteraction :: Maybe Text
    , _cvss30_modifiedScope :: Maybe Text
    , _cvss30_modifiedConfidentialityImpact :: Maybe Text
    , _cvss30_modifiedIntegrityImpact :: Maybe Text
    , _cvss30_modifiedAvailabilityImpact :: Maybe Text
    , _cvss30_environmentalScore :: Maybe Text
    , _cvss30_environmentalSeverity :: Maybe Text
    } deriving (Show, Eq, Ord, Generic)

data CVSS20 = CVSS0
    { _cvss20_version :: Text
    , _cvss20_vectorString :: Text
    , _cvss20_accessVector :: Maybe Text
    , _cvss20_accessComplexity :: Maybe Text
    , _cvss20_authentication :: Maybe Text
    , _cvss20_confidentialityImpact :: Maybe Text
    , _cvss20_integrityImpact :: Maybe Text
    , _cvss20_availabilityImpact :: Maybe Text
    , _cvss20_baseScore :: Double
    , _cvss20_exploitability :: Maybe Text
    , _cvss20_remediationLevel :: Maybe Text
    , _cvss20_reportConfidence :: Maybe Text
    , _cvss20_temporalScore :: Maybe Text
    , _cvss20_collateralDamagePotential :: Maybe Text
    , _cvss20_targetDistribution :: Maybe Text
    , _cvss20_confidentialityRequirement :: Maybe Text
    , _cvss20_integrityRequirement :: Maybe Text
    , _cvss20_availabilityRequirement :: Maybe Text
    , _cvss20_environmentalScore :: Maybe Text
    } deriving (Show, Eq, Ord, Generic)

data TimeLine = TimeLine
  { _timeline_time :: Text
  , _timeline_lang :: Text
  , _timeline_value :: Text
  } deriving (Show, Eq, Ord, Generic)

data Credit = Credit
  { _credit_lang :: Text
  , _credit_value :: Text
  , _credit_user :: Maybe Text
  , _credit_type :: Maybe Text
  } deriving (Show, Eq, Ord, Generic)

data TaxonomyMapping = TaxonomyMapping
  { _taxonomymapping_taxonomyName :: Text
  , _taxonomymapping_taxonomyVersion :: Maybe Text
  , _taxonomymapping_taxonomyRelations :: [TaxonomyRelation]
  } deriving (Show, Eq, Ord, Generic)

data TaxonomyRelation = TaxonomyRelation
  { _taxonomyrelation_taxonomyId :: Text
  , _taxonomyrelation_relationshipName :: Text
  , _taxonomyrelation_relationshipValue :: Text
  } deriving (Show, Eq, Ord, Generic)

data CPE = CPE
  { _cpe_cpeVersion :: Text
  , _cpe_part :: Text
  , _cpe_vendor :: Text
  , _cpe_product :: Text
  , _cpe_version :: Text
  , _cpe_update :: Text
  , _cpe_edition :: Text
  , _cpe_lang :: Text
  , _cpe_sw_edition :: Text
  , _cpe_tgt_sw :: Text
  , _cpe_tgt_hw :: Text
  , _cpe_extra :: Text
  } deriving (Show, Generic)

parseCPE :: Text -> Maybe CPE
parseCPE = parse . T.splitOn ":"
  where
      parse = \case
        [_, cpe_version, part, vendor, product', version, update, edition, language, sw_ed, tgt_sw, tgt_hw, extra] -> Just $ CPE cpe_version part vendor product' version update edition language sw_ed tgt_sw tgt_hw extra
        _ -> Nothing


mconcat <$> sequence (deriveJSON stripType' <$>
    [ ''CVE
    , ''CVEMetadata
    , ''Container
    , ''CNA
    , ''ADP
    , ''ProviderMetadata
    , ''Description
    , ''SupportingMedia
    , ''Product
    , ''Version
    , ''Change
    , ''ProblemType
    , ''ProblemDescription
    , ''Reference
    , ''Impact
    , ''Metric
    , ''Scenario
    , ''CVSS31
    , ''CVSS30
    , ''CVSS20
    , ''TimeLine
    , ''Credit
    , ''TaxonomyMapping
    , ''TaxonomyRelation
    , ''ProgramRoutine
    ])
