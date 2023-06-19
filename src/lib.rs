use std::fmt::Debug;
use std::fs::File;
use std::io::BufReader;

use serde::Deserialize;

use crate::errors::Error;

mod errors;

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
    weaknesses: Weaknesses,
    #[serde(rename = "Categories")]
    categories: Categories,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Weaknesses")]
#[serde(deny_unknown_fields)]
pub struct Weaknesses {
    #[serde(rename = "Weakness", default)]
    weaknesses: Vec<Weakness>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Categories")]
pub struct Categories {
    #[serde(rename = "Category", default)]
    categories: Vec<Category>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Weakness")]
// #[serde(deny_unknown_fields)]
pub struct Weakness {
    #[serde(rename = "@ID")]
    id: String,
    #[serde(rename = "@Name")]
    name: String,
    #[serde(rename = "@Abstraction")]
    abstraction: String,
    #[serde(rename = "@Structure")]
    structure: String,
    #[serde(rename = "@Status")]
    status: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "Extended_Description")]
    extended_description: Option<ExtendedDescription>,
    #[serde(rename = "Related_Weaknesses")]
    related_weaknesses: RelatedWeaknesses,
    #[serde(rename = "Demonstrative_Examples")]
    demonstrative_examples: Option<DemonstrativeExamples>,
    #[serde(rename = "Weakness_Ordinalities")]
    weakness_ordinalities: Option<WeaknessOrdinalities>,
    #[serde(rename = "Applicable_Platforms")]
    applicable_platforms: Option<ApplicablePlatforms>,
    #[serde(rename = "Background_Details")]
    background_details: Option<BackgroundDetails>,
    #[serde(rename = "Modes_Of_Introduction")]
    modes_of_introduction: Option<ModesOfIntroduction>,
    #[serde(rename = "Likelihood_Of_Exploit")]
    likelihood_of_exploit: Option<String>,
    #[serde(rename = "Alternate_Terms")]
    alternate_terms: Option<AlternateTerms>,
    #[serde(rename = "Common_Consequences")]
    common_consequences: Option<CommonConsequences>,
    #[serde(rename = "Detection_Methods")]
    detection_methods: Option<DetectionMethods>,
    #[serde(rename = "Potential_Mitigations")]
    potential_mitigations: Option<PotentialMitigations>,
    #[serde(rename = "Observed_Examples")]
    observed_examples: Option<ObservedExamples>,
    #[serde(rename = "Related_Attack_Patterns")]
    related_attack_patterns: Option<RelatedAttackPatterns>,
    #[serde(rename = "References")]
    references: Option<References>,
    #[serde(rename = "Content_History")]
    content_history: ContentHistory,
}

#[derive(Debug, Deserialize)]
pub struct ContentHistory {
    #[serde(rename = "$value")]
    references: Vec<ContentHistoryChild>,
}

#[derive(Debug, Deserialize)]
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
pub struct Submission {
    #[serde(rename = "Submission_Name")]
    submission_name: String,
    #[serde(rename = "Submission_Organization")]
    submission_organization: Option<String>,
    #[serde(rename = "Submission_Date")]
    submission_date: String,
}

#[derive(Debug, Deserialize)]
pub struct Modification {
    #[serde(rename = "Modification_Name")]
    modification_name: String,
    #[serde(rename = "Modification_Organization")]
    modification_organization: String,
    #[serde(rename = "Modification_Date")]
    modification_date: String,
    #[serde(rename = "Modification_Comment")]
    modification_comment: String,
}

#[derive(Debug, Deserialize)]
pub struct Contribution {
    #[serde(rename = "@Type")]
    r#type: Option<String>,
    #[serde(rename = "Contribution_Name")]
    contribution_name: String,
    #[serde(rename = "Contribution_Organization")]
    contribution_organization: Option<String>,
    #[serde(rename = "Contribution_Date")]
    contribution_date: String,
    #[serde(rename = "Contribution_Comment")]
    contribution_comment: String,
}

#[derive(Debug, Deserialize)]
pub struct References {
    #[serde(rename = "$value")]
    references: Vec<Reference>,
}

#[derive(Debug, Deserialize)]
pub struct Reference {
    #[serde(rename = "@External_Reference_ID")]
    external_reference_id: String,
    #[serde(rename = "@Section")]
    section: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RelatedAttackPatterns {
    #[serde(rename = "$value")]
    related_attack_patterns: Vec<RelatedAttackPattern>,
}

#[derive(Debug, Deserialize)]
pub struct RelatedAttackPattern {
    #[serde(rename = "@CAPEC_ID")]
    caped_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ObservedExamples {
    #[serde(rename = "$value")]
    observed_examples: Vec<ObservedExample>,
}

#[derive(Debug, Deserialize)]
pub struct ObservedExample {
    #[serde(rename = "Reference")]
    reference: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "Link")]
    link: String,
}

#[derive(Debug, Deserialize)]
pub struct DemonstrativeExamples {
    #[serde(rename = "Demonstrative_Example")]
    examples: Vec<DemonstrativeExample>,
}

#[derive(Debug, Deserialize)]
pub struct DemonstrativeExample {
    #[serde(rename = "$value")]
    children: Vec<DemonstrativeExampleChild>,
}

#[derive(Debug, Deserialize)]
pub enum DemonstrativeExampleChild {
    #[serde(rename = "Intro_Text")]
    IntroText {
        #[serde(rename = "$value")]
        children: Vec<ExtendedTextNode>,
    },
    #[serde(rename = "Body_Text")]
    BodyText {
        #[serde(rename = "$value")]
        children: Vec<ExtendedTextNode>,
    },
    #[serde(rename = "Example_Code")]
    ExampleCode(ExampleCode),
}

#[derive(Debug, Deserialize)]
pub struct ExampleCode {
    #[serde(rename = "@Nature")]
    nature: String,
    #[serde(rename = "@Language")]
    language: Option<String>,
    #[serde(rename = "$value")]
    children: Vec<ExtendedTextNode>,
}

#[derive(Debug, Deserialize)]
pub struct PotentialMitigations {
    #[serde(rename = "$value")]
    potential_mitigations: Vec<PotentialMitigation>,
}

#[derive(Debug, Deserialize)]
pub struct PotentialMitigation {
    #[serde(rename = "$value")]
    children: Vec<PotentialMitigationChild>,
}

#[derive(Debug, Deserialize)]
pub enum PotentialMitigationChild {
    #[serde(rename = "Phase")]
    Phase(String),
    #[serde(rename = "Strategy")]
    Strategy(String),
    #[serde(rename = "Description")]
    Description(ExtendedDescription),
    #[serde(rename = "Effectiveness")]
    Effectiveness(String),
    #[serde(rename = "Effectiveness_Notes")]
    EffectivenessNotes(String),
}

#[derive(Debug, Deserialize)]
pub struct DetectionMethods {
    #[serde(rename = "$value")]
    detection_methods: Vec<DetectionMethod>,
}

#[derive(Debug, Deserialize)]
pub struct DetectionMethod {
    #[serde(rename = "$value")]
    children: Vec<DetectionMethodChild>,
}

#[derive(Debug, Deserialize)]
pub enum DetectionMethodChild {
    #[serde(rename = "Method")]
    Method(String),
    #[serde(rename = "Description")]
    Description {
        #[serde(rename = "$value")]
        children: Vec<ExtendedTextNode>,
    },
    #[serde(rename = "Effectiveness")]
    Effectiveness(String),
    #[serde(rename = "Effectiveness_Notes")]
    EffectivenessNotes(String),
}

#[derive(Debug, Deserialize)]
pub struct CommonConsequences {
    #[serde(rename = "$value")]
    common_consequences: Vec<Consequence>,
}

#[derive(Debug, Deserialize)]
pub struct Consequence {
    #[serde(rename = "$value")]
    children: Vec<ConsequenceChild>,
}

#[derive(Debug, Deserialize)]
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
pub struct AlternateTerms {
    #[serde(rename = "$value")]
    alternate_terms: Vec<AlternateTerm>,
}

#[derive(Debug, Deserialize)]
pub struct AlternateTerm {
    #[serde(rename = "Term")]
    term: String,
    #[serde(rename = "Description")]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ModesOfIntroduction {
    #[serde(rename = "$value")]
    introductions: Vec<Introduction>,
}

#[derive(Debug, Deserialize)]
pub struct Introduction {
    #[serde(rename = "Phase")]
    phase: String,
    #[serde(rename = "Note")]
    note: Option<Note>,
}

#[derive(Debug, Deserialize)]
pub struct Note {
    #[serde(rename = "$value")]
    text: Vec<ExtendedTextNode>,
}

#[derive(Debug, Deserialize)]
pub struct BackgroundDetails {
    #[serde(rename = "$value")]
    background_details: Vec<BackgroundDetail>,
}

#[derive(Debug, Deserialize)]
pub struct BackgroundDetail {
    #[serde(rename = "$value")]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApplicablePlatforms {
    #[serde(rename = "$value")]
    applicable_platforms: Vec<ApplicablePlatform>,
}

#[derive(Debug, Deserialize)]
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
        #[serde(rename = "@Class")]
        class: Option<String>,
        #[serde(rename = "@Prevalence")]
        prevalence: String,
    },
    #[serde(rename = "Operating_System")]
    OperatingSystem {
        #[serde(rename = "@Class")]
        class: Option<String>,
        #[serde(rename = "@Prevalence")]
        prevalence: String,
    },
    #[serde(rename = "Architecture")]
    Architecture {
        #[serde(rename = "@Class")]
        class: Option<String>,
        #[serde(rename = "@Prevalence")]
        prevalence: String,
    },
}

#[derive(Debug, Deserialize)]
pub struct WeaknessOrdinalities {
    #[serde(rename = "$value")]
    weakness_ordinalities: Vec<WeaknessOrdinality>,
}

#[derive(Debug, Deserialize)]
pub struct WeaknessOrdinality {
    #[serde(rename = "Ordinality")]
    ordinality: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Extended_Description")]
pub struct ExtendedDescription {
    #[serde(rename = "$value")]
    descriptions: Vec<ExtendedTextNode>,
}

#[derive(Debug, Deserialize)]
pub enum ExtendedTextNode {
    #[serde(rename = "p")]
    P {
        #[serde(rename = "$value")]
        children: Vec<Box<ExtendedTextNode>>,
    },
    #[serde(rename = "ol")]
    XhtmlOl {
        #[serde(rename = "$value")]
        children: Vec<Box<ExtendedTextNode>>,
    },
    #[serde(rename = "li")]
    XhtmlLi {
        #[serde(rename = "$value")]
        children: Vec<Box<ExtendedTextNode>>,
    },
    #[serde(rename = "ul")]
    XhtmlUl {
        #[serde(rename = "$value")]
        children: Vec<Box<ExtendedTextNode>>,
    },
    #[serde(rename = "div")]
    XhtmlDiv {
        #[serde(rename = "@style")]
        style: Option<String>,
        #[serde(rename = "$value")]
        children: Vec<Box<ExtendedTextNode>>,
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
pub struct RelatedWeaknesses {
    #[serde(rename = "Related_Weakness", default)]
    related_weaknesses: Vec<RelatedWeakness>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Related_Weakness")]
pub struct RelatedWeakness {
    #[serde(rename = "@Nature")]
    nature: String,
    #[serde(rename = "@CWE_ID")]
    cwe_id: String,
    #[serde(rename = "@View_ID")]
    view_id: String,
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
    has_members: Vec<HasMember>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Has_Member")]
pub struct HasMember {
    #[serde(rename = "@CWE_ID")]
    cwe_id: String,
    #[serde(rename = "@View_ID")]
    view_id: String,
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
