use serde::Deserialize;
use crate::{AffectedResources, AlternateTerms, ApplicablePlatforms, BackgroundDetails, CommonConsequences, ContentHistory, DemonstrativeExamples, DetectionMethods, ExploitationFactors, FunctionalAreas, ModesOfIntroduction, Notes, ObservedExamples, PotentialMitigations, References, RelatedAttackPatterns, RelatedWeaknesses, StructuredText, TaxonomyMappings, WeaknessOrdinalities};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weaknesses {
    #[serde(rename = "Weakness", default)]
    pub weaknesses: Vec<Weakness>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Weakness")]
#[serde(deny_unknown_fields)]
pub struct Weakness {
    #[serde(rename = "@ID")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Abstraction")]
    pub abstraction: String,
    #[serde(rename = "@Structure")]
    pub structure: String,
    #[serde(rename = "@Status")]
    pub status: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Extended_Description")]
    pub extended_description: Option<StructuredText>,
    #[serde(rename = "Related_Weaknesses")]
    pub related_weaknesses: Option<RelatedWeaknesses>,
    #[serde(rename = "Demonstrative_Examples")]
    pub demonstrative_examples: Option<DemonstrativeExamples>,
    #[serde(rename = "Weakness_Ordinalities")]
    pub weakness_ordinalities: Option<WeaknessOrdinalities>,
    #[serde(rename = "Applicable_Platforms")]
    pub applicable_platforms: Option<ApplicablePlatforms>,
    #[serde(rename = "Background_Details")]
    pub background_details: Option<BackgroundDetails>,
    #[serde(rename = "Modes_Of_Introduction")]
    pub modes_of_introduction: Option<ModesOfIntroduction>,
    #[serde(rename = "Likelihood_Of_Exploit")]
    pub likelihood_of_exploit: Option<String>,
    #[serde(rename = "Alternate_Terms")]
    pub alternate_terms: Option<AlternateTerms>,
    #[serde(rename = "Common_Consequences")]
    pub common_consequences: Option<CommonConsequences>,
    #[serde(rename = "Detection_Methods")]
    pub detection_methods: Option<DetectionMethods>,
    #[serde(rename = "Potential_Mitigations")]
    pub potential_mitigations: Option<PotentialMitigations>,
    #[serde(rename = "Observed_Examples")]
    pub observed_examples: Option<ObservedExamples>,
    #[serde(rename = "Related_Attack_Patterns")]
    pub related_attack_patterns: Option<RelatedAttackPatterns>,
    #[serde(rename = "References")]
    pub references: Option<References>,
    #[serde(rename = "Content_History")]
    pub content_history: ContentHistory,
    #[serde(rename = "Exploitation_Factors")]
    pub exploitation_factors: Option<ExploitationFactors>,
    #[serde(rename = "Functional_Areas")]
    pub functional_areas: Option<FunctionalAreas>,
    #[serde(rename = "Affected_Resources")]
    pub affected_resources: Option<AffectedResources>,
    #[serde(rename = "Taxonomy_Mappings")]
    pub taxonomy_mappings: Option<TaxonomyMappings>,
    #[serde(rename = "Notes")]
    pub notes: Option<Notes>,
}
