use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn read_data_from_file_at_line(file_path: &str, line_number: usize) -> Result<Option<(Vec<u8>, Vec<u8>)>, Box<dyn Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut current_line = 0;

    for line in reader.lines() {
        let line = line?;
        if current_line == line_number {
            let parts: Vec<&str> = line.split_whitespace().collect();
            println!("Debug: parts = {:?}", parts); // Print parts for debugging
            if parts.len() == 2 {
                let address = parts[0].as_bytes().to_vec();
                let balance = parts[1].parse::<u128>().map(|v| v.to_le_bytes().to_vec()).map_err(|e| Box::new(e) as Box<dyn Error>)?;
                return Ok(Some((address, balance)));
            } else {
                eprintln!("Invalid line format: {}", line);
                return Ok(None);
            }
        }
        current_line += 1;
    }

    Ok(None)
}
