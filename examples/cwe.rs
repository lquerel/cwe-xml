use std::io::Read;
use cwe_xml::cwe::CweDatabase;

/// Download the CWE catalogs, parse them, build a global CweCatalog struct and print it.
/// CWE files are zipped XML files.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cwe_db = CweDatabase::new();

    // Import the 3 main CWE catalogs from the official website.
    cwe_db.import_weakness_catalog_from_str(&download_xml("https://cwe.mitre.org/data/xml/views/699.xml.zip")?)?;
    cwe_db.import_weakness_catalog_from_str(&download_xml("https://cwe.mitre.org/data/xml/views/1000.xml.zip")?)?;
    cwe_db.import_weakness_catalog_from_str(&download_xml("https://cwe.mitre.org/data/xml/views/1194.xml.zip")?)?;

    // Retrieve a weakness by its ID (CWE-73).
    let cwe_id: i64 = 306;
    let weakness = cwe_db.weakness_by_cwe_id(cwe_id);
    println!("Weakness CWE-ID-{}\n{:#?}", cwe_id, weakness);

    // Display the categories of the weakness (if any).
    let categories = cwe_db.categories_by_cwe_id(cwe_id);
    if let Some(categories) = categories {
        println!("Categories {:#?}", categories);
    }

    // Display the CWE catalog summary.
    println!("{}", cwe_db);

    Ok(())
}

fn download_xml(file :&str) -> Result<String, Box<dyn std::error::Error>> {
    let mut tmp_file = tempfile::tempfile()?;
    let mut xml = String::new();

    reqwest::blocking::get(file)?
        .copy_to(&mut tmp_file)?;
    let mut zip_archive = zip::ZipArchive::new(tmp_file)?;
    zip_archive
        .by_index(0)?
        .read_to_string(&mut xml)?;
    Ok(xml)
}