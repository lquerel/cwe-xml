use std::rc::Rc;
use serde::Deserialize;
use crate::cwe::content_history::ContentHistory;
use crate::cwe::notes::Notes;
use crate::cwe::relationships::Relationships;
use crate::cwe::structured_text::StructuredText;
use crate::cwe::weaknesses::MappingNotes;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Views {
    #[serde(rename = "$value", default)]
    pub views: Vec<Rc<View>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct View {
    #[serde(rename = "@ID")]
    pub id: i64,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Type")]
    pub r#type: String,
    #[serde(rename = "@Status")]
    pub status: String,
    #[serde(rename = "Objective")]
    pub objective: StructuredText,
    #[serde(rename = "Audience")]
    pub audience: Option<Audience>,
    #[serde(rename = "Members")]
    pub members: Option<Relationships>,
    #[serde(rename = "Notes")]
    pub notes: Option<Notes>,
    #[serde(rename = "Filter")]
    pub filter: Option<String>,
    #[serde(rename = "Content_History")]
    pub content_history: ContentHistory,
    #[serde(rename = "Mapping_Notes")]
    pub mapping_notes: Option<MappingNotes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audience {
    #[serde(rename = "$value", default)]
    pub stake_holders: Vec<StakeHolder>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StakeHolder {
    #[serde(rename = "Type")]
    pub r#type: String,
    #[serde(rename = "Description")]
    pub description: Option<String>,
}
