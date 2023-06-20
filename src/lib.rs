use std::fmt::Debug;
use std::fs::File;
use std::io::BufReader;

use serde::Deserialize;
use external_references::ExternalReferences;
use views::Views;
use weaknesses::Weaknesses;

use crate::errors::Error;

pub mod errors;
pub mod views;
pub mod external_references;
pub mod weaknesses;

#[derive(Debug, Deserialize)]
#[serde(rename = "Weakness_Catalog")]
#[serde(deny_unknown_fields)]
pub struct WeaknessCatalog {
    #[serde(rename = "@xmlns")]
    xmlns: String,
    #[serde(rename = "@xmlns:xhtml")]
    xhtml: String,
    #[serde(rename = "@xmlns:xsi")]
    xsi: String,
    #[serde(rename = "@schemaLocation")]
    schema_location: String,
    #[serde(rename = "@Name")]
    name: String,
    #[serde(rename = "@Version")]
    version: String,
    #[serde(rename = "@Date")]
    date: String,
    #[serde(rename = "Weaknesses")]
    weaknesses: Option<Weaknesses>,
    #[serde(rename = "Categories")]
    categories: Option<Categories>,
    #[serde(rename = "Views")]
    views: Option<Views>,
    #[serde(rename = "External_References")]
    external_references: Option<ExternalReferences>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Categories")]
pub struct Categories {
    #[serde(rename = "Category", default)]
    categories: Vec<Category>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notes {
    #[serde(rename = "$value")]
    pub notes: Vec<Note>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    #[serde(rename = "@Type")]
    pub r#type: Option<String>,
    #[serde(rename = "$value")]
    pub content: Vec<StructuredTextType>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyMappings {
    #[serde(rename = "$value")]
    pub taxonomy_mappings: Vec<TaxonomyMapping>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyMapping {
    #[serde(rename = "@Taxonomy_Name")]
    pub taxonomy_name: String,
    #[serde(rename = "Entry_ID")]
    pub entry_id: Option<String>,
    #[serde(rename = "Entry_Name")]
    pub entry_name: Option<String>,
    #[serde(rename = "Mapping_Fit")]
    pub mapping_fit: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionalAreas {
    #[serde(rename = "$value")]
    functional_areas: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedResources {
    #[serde(rename = "$value")]
    affected_resources: Vec<String>,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentHistory {
    #[serde(rename = "$value")]
    pub references: Vec<ContentHistoryChild>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ContentHistoryChild {
    #[serde(rename = "Submission")]
    Submission(Submission),
    #[serde(rename = "Modification")]
    Modification(Modification),
    #[serde(rename = "Contribution")]
    Contribution(Contribution),
    #[serde(rename = "Previous_Entry_Name")]
    PreviousEntryName {
        #[serde(rename = "@Date")]
        date: String,
        #[serde(rename = "$value")]
        previous_entry_name: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    #[serde(rename = "Submission_Name")]
    submission_name: String,
    #[serde(rename = "Submission_Organization")]
    submission_organization: Option<String>,
    #[serde(rename = "Submission_Date")]
    submission_date: String,
    #[serde(rename = "Submission_Comment")]
    submission_comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Modification {
    #[serde(rename = "Modification_Name")]
    modification_name: Option<String>,
    #[serde(rename = "Modification_Organization")]
    modification_organization: Option<String>,
    #[serde(rename = "Modification_Date")]
    modification_date: String,
    #[serde(rename = "Modification_Importance")]
    modification_importance: Option<String>,
    #[serde(rename = "Modification_Comment")]
    modification_comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contribution {
    #[serde(rename = "@Type")]
    r#type: Option<String>,
    #[serde(rename = "Contribution_Name")]
    contribution_name: Option<String>,
    #[serde(rename = "Contribution_Organization")]
    contribution_organization: Option<String>,
    #[serde(rename = "Contribution_Date")]
    contribution_date: String,
    #[serde(rename = "Contribution_Comment")]
    contribution_comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct References {
    #[serde(rename = "$value")]
    references: Vec<Reference>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    #[serde(rename = "@External_Reference_ID")]
    external_reference_id: String,
    #[serde(rename = "@Section")]
    section: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedAttackPatterns {
    #[serde(rename = "$value")]
    related_attack_patterns: Vec<RelatedAttackPattern>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedAttackPattern {
    #[serde(rename = "@CAPEC_ID")]
    caped_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedExamples {
    #[serde(rename = "$value")]
    observed_examples: Vec<ObservedExample>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedExample {
    #[serde(rename = "Reference")]
    reference: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "Link")]
    link: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemonstrativeExamples {
    #[serde(rename = "Demonstrative_Example")]
    examples: Vec<DemonstrativeExample>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemonstrativeExample {
    #[serde(rename = "@Demonstrative_Example_ID")]
    demonstrative_example_id: Option<String>,
    #[serde(rename = "$value")]
    children: Vec<DemonstrativeExampleChild>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DemonstrativeExampleChild {
    #[serde(rename = "Title_Text")]
    TitleText(String),
    #[serde(rename = "Intro_Text")]
    IntroText(StructuredText),
    #[serde(rename = "Body_Text")]
    BodyText(StructuredText),
    #[serde(rename = "Example_Code")]
    ExampleCode, // ToDo (StructuredCode), <-- doesn't work, quick-xml limit?
    #[serde(rename = "References")]
    References {
        #[serde(rename = "$value")]
        children: Vec<Reference>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredCode {
    #[serde(rename = "@Nature")]
    nature: String,
    #[serde(rename = "@Language")]
    language: Option<String>,
    #[serde(rename = "$value", default)]
    children: Option<Vec<StructuredTextType>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PotentialMitigations {
    #[serde(rename = "$value")]
    potential_mitigations: Vec<PotentialMitigation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PotentialMitigation {
    #[serde(rename = "@Mitigation_ID")]
    mitigation_id: Option<String>,
    #[serde(rename = "$value")]
    children: Vec<PotentialMitigationChild>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PotentialMitigationChild {
    #[serde(rename = "Phase")]
    Phase(String),
    #[serde(rename = "Strategy")]
    Strategy(String),
    #[serde(rename = "Description")]
    Description(StructuredText),
    #[serde(rename = "Effectiveness")]
    Effectiveness(String),
    #[serde(rename = "Effectiveness_Notes")]
    EffectivenessNotes(StructuredText),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionMethods {
    #[serde(rename = "$value")]
    detection_methods: Vec<DetectionMethod>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionMethod {
    #[serde(rename = "@Detection_Method_ID")]
    detection_method_id: Option<String>,
    #[serde(rename = "$value")]
    children: Vec<DetectionMethodChild>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DetectionMethodChild {
    #[serde(rename = "Method")]
    Method(String),
    #[serde(rename = "Description")]
    Description(StructuredText),
    #[serde(rename = "Effectiveness")]
    Effectiveness(String),
    #[serde(rename = "Effectiveness_Notes")]
    EffectivenessNotes(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonConsequences {
    #[serde(rename = "$value")]
    common_consequences: Vec<Consequence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consequence {
    #[serde(rename = "$value")]
    children: Vec<ConsequenceChild>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ConsequenceChild {
    #[serde(rename = "Scope")]
    Scope(String),
    #[serde(rename = "Impact")]
    Impact(String),
    #[serde(rename = "Note")]
    Note(String),
    #[serde(rename = "Likelihood")]
    Likelihood(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateTerms {
    #[serde(rename = "$value")]
    alternate_terms: Vec<AlternateTerm>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExploitationFactors {
    #[serde(rename = "$value")]
    children: Vec<StructuredText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateTerm {
    #[serde(rename = "Term")]
    term: String,
    #[serde(rename = "Description")]
    description: Option<StructuredText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModesOfIntroduction {
    #[serde(rename = "$value")]
    introductions: Vec<Introduction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Introduction {
    #[serde(rename = "Phase")]
    phase: String,
    #[serde(rename = "Note")]
    note: Option<StructuredText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackgroundDetails {
    #[serde(rename = "$value")]
    background_details: StructuredText,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicablePlatforms {
    #[serde(rename = "$value")]
    applicable_platforms: Vec<ApplicablePlatform>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ApplicablePlatform {
    Language {
        #[serde(rename = "@Class")]
        class: Option<String>,
        #[serde(rename = "@Name")]
        name: Option<String>,
        #[serde(rename = "@Prevalence")]
        prevalence: String,
    },
    Technology {
        #[serde(rename = "@Name")]
        name: Option<String>,
        #[serde(rename = "@Class")]
        class: Option<String>,
        #[serde(rename = "@Prevalence")]
        prevalence: String,
    },
    #[serde(rename = "Operating_System")]
    OperatingSystem {
        #[serde(rename = "@Name")]
        name: Option<String>,
        #[serde(rename = "@Version")]
        version: Option<String>,
        #[serde(rename = "@CPE_ID")]
        cpe_id: Option<String>,
        #[serde(rename = "@Class")]
        class: Option<String>,
        #[serde(rename = "@Prevalence")]
        prevalence: String,
    },
    #[serde(rename = "Architecture")]
    Architecture {
        #[serde(rename = "@Name")]
        name: Option<String>,
        #[serde(rename = "@Class")]
        class: Option<String>,
        #[serde(rename = "@Prevalence")]
        prevalence: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeaknessOrdinalities {
    #[serde(rename = "$value")]
    weakness_ordinalities: Vec<WeaknessOrdinality>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeaknessOrdinality {
    #[serde(rename = "Ordinality")]
    ordinality: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredText {
    #[serde(rename = "$value")]
    descriptions: Vec<StructuredTextType>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum StructuredTextType {
    #[serde(rename = "p")]
    P {
        #[serde(rename = "$value")]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "b")]
    XhtmlB {
        #[serde(rename = "$value")]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "ol")]
    XhtmlOl {
        #[serde(rename = "$value")]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "li")]
    XhtmlLi {
        #[serde(rename = "$value")]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "ul")]
    XhtmlUl {
        #[serde(rename = "$value")]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "table")]
    XhtmlTable {
        #[serde(rename = "$value")]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "tr")]
    XhtmlTr {
        #[serde(rename = "$value")]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "th")]
    XhtmlTh {
        #[serde(rename = "$value")]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "td")]
    XhtmlTd {
        #[serde(rename = "$value")]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "img")]
    XhtmlImg {
        #[serde(rename = "@src")]
        src: String,
        #[serde(rename = "@alt")]
        alt: Option<String>,
    },
    #[serde(rename = "div")]
    XhtmlDiv {
        #[serde(rename = "@style")]
        style: Option<String>,
        #[serde(rename = "$value")]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "br")]
    XhtmlBr,
    #[serde(rename = "i")]
    XhtmlI {
        #[serde(rename = "$value")]
        text: String,
    },
    #[serde(rename = "$text")]
    String(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Related_Weaknesses")]
#[serde(deny_unknown_fields)]
pub struct RelatedWeaknesses {
    #[serde(rename = "Related_Weakness", default)]
    related_weaknesses: Vec<RelatedWeakness>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Related_Weakness")]
#[serde(deny_unknown_fields)]
pub struct RelatedWeakness {
    #[serde(rename = "@Nature")]
    nature: String,
    #[serde(rename = "@CWE_ID")]
    cwe_id: String,
    #[serde(rename = "@View_ID")]
    view_id: String,
    #[serde(rename = "@Chain_ID")]
    chain_id: Option<String>,
    #[serde(rename = "@Ordinal")]
    ordinal: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Category")]
pub struct Category {
    #[serde(rename = "@ID")]
    id: String,
    #[serde(rename = "@Name")]
    name: String,
    #[serde(rename = "@Status")]
    status: String,
    #[serde(rename = "Summary")]
    summary: String,
    #[serde(rename = "Relationships")]
    relationships: Relationships,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Relationships")]
pub struct Relationships {
    #[serde(rename = "Has_Member", default)]
    pub has_members: Vec<HasMember>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Has_Member")]
pub struct HasMember {
    #[serde(rename = "@CWE_ID")]
    pub cwe_id: String,
    #[serde(rename = "@View_ID")]
    pub view_id: String,
}

#[derive(Debug)]
pub struct CweDb {
    weakness_catalog: WeaknessCatalog,
}

impl CweDb {
    pub fn from_file(xml_file: &str) -> Result<CweDb, Error> {
        let file = File::open(xml_file).map_err(|e| Error::InvalidCweFile {
            file: xml_file.to_string(),
            error: e.to_string(),
        })?;
        let reader = BufReader::new(file);
        let weakness_catalog: WeaknessCatalog = quick_xml::de::from_reader(reader).map_err(|e| Error::InvalidCweFile {
            file: xml_file.to_string(),
            error: e.to_string(),
        })?;
        Ok(CweDb { weakness_catalog })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_file() {
        let cwe_db = match CweDb::from_file("data/699.xml") {
            Ok(cwe_db) => cwe_db,
            Err(e) => {
                panic!("Error: {:?}", e)
            }
        };
        // format debug output
        let output = format!("{:#?}", cwe_db);
        println!("{}", output);
    }
}
