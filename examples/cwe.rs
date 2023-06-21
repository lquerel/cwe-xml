use std::io::Read;
use cwe_xml::cwe::CweCatalog;

/// Download the CWE catalog, parse it, build a CweCatalog struct and print it.
/// CWE files are zipped XML files.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut tmp_file = tempfile::tempfile()?;
    let mut xml = String::new();

    reqwest::blocking::get("https://cwe.mitre.org/data/xml/views/699.xml.zip")?
        .copy_to(&mut tmp_file)?;
    let mut zip_archive = zip::ZipArchive::new(tmp_file)?;
    zip_archive
        .by_index(0)?
        .read_to_string(&mut xml)?;

    let cwes = match CweCatalog::from_str(&xml) {
        Ok(cwe_db) => cwe_db,
        Err(e) => {
            panic!("Error: {:?}", e)
        }
    };

    println!("{} weaknesses loaded", cwes.weakness_catalog.weaknesses.unwrap().weaknesses.len());
    println!("{} categories loaded", cwes.weakness_catalog.categories.unwrap().categories.len());
    println!("{} views loaded", cwes.weakness_catalog.views.unwrap().views.len());
    println!("{} external references loaded", cwes.weakness_catalog.external_references.unwrap().external_references.len());

    Ok(())
}