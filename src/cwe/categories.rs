use std::hash::{Hash};
use std::rc::Rc;
use serde::Deserialize;
use crate::cwe::relationships::Relationships;

#[derive(Debug, Deserialize)]
pub struct Categories {
    #[serde(rename = "Category", default)]
    pub categories: Vec<Rc<Category>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Category")]
pub struct Category {
    #[serde(rename = "@ID")]
    pub id: i64,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Status")]
    pub status: String,
    #[serde(rename = "Summary")]
    pub summary: String,
    #[serde(rename = "Relationships")]
    pub relationships: Relationships,
}

impl PartialEq for Category {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Category {}

impl Hash for Category {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_i64(self.id);
    }
}