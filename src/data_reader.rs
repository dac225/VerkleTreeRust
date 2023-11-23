use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn read_data_from_file(file_path: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Box<dyn Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut data: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 {
            let address = parts[0].to_string().chars().map(|c| c as u8).collect();
            let balance = parts[1]
                .parse()
                .map_err(|e| Box::new(e) as Box<dyn Error>)?;
            data.push((address, vec![balance]));
        } else {
            eprintln!("Invalid line format: {}", line);
        }
    }

    Ok(data)
}