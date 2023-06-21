use std::rc::Rc;
use serde::Deserialize;
use crate::cwe::categories::Categories;
use crate::cwe::external_references::ExternalReferences;
use crate::cwe::views::Views;
use crate::cwe::weaknesses::Weaknesses;

#[derive(Debug, Deserialize)]
#[serde(rename = "Weakness_Catalog")]
pub struct WeaknessCatalog {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Version")]
    pub version: String,
    #[serde(rename = "@Date")]
    pub date: String,
    #[serde(rename = "Weaknesses")]
    pub weaknesses: Option<Weaknesses>,
    #[serde(rename = "Categories")]
    pub categories: Option<Categories>,
    #[serde(rename = "Views")]
    pub views: Option<Views>,
    #[serde(rename = "External_References")]
    pub external_references: Option<ExternalReferences>,
}
