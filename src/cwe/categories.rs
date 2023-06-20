use serde::Deserialize;
use crate::cwe::relationships::Relationships;

#[derive(Debug, Deserialize)]
pub struct Categories {
    #[serde(rename = "Category", default)]
    pub categories: Vec<Category>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Category")]
pub struct Category {
    #[serde(rename = "@ID")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Status")]
    pub status: String,
    #[serde(rename = "Summary")]
    pub summary: String,
    #[serde(rename = "Relationships")]
    pub relationships: Relationships,
}
