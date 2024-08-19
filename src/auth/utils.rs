use chrono::Duration;

pub enum ParseDurationError {
    InvalidDurationFormat(String),
}

pub fn parse_duration_from_string(input_duration: &str) -> Result<Duration, ParseDurationError> {
    // convert 1d to 1 day -> 24 hours -> 1440 minutes -> 86400 seconds, 1y to 1 year -> 365 days -> 8760 hours -> 525600 minutes -> 31536000 seconds
    // etc.

    if input_duration.is_empty() {
        return Err(ParseDurationError::InvalidDurationFormat(input_duration.to_string()));
    }

    if input_duration.chars().all(|c| !c.is_numeric()) {
        return Err(ParseDurationError::InvalidDurationFormat(input_duration.to_string()));
    }

    let mut duration = Duration::zero();
    let mut current_number = String::new();
    for c in input_duration.chars() {
        if c.is_numeric() {
            current_number.push(c);
        } else {
            let number = if let Ok(number) = current_number.parse::<i64>() {
                number
            } else {
                return Err(ParseDurationError::InvalidDurationFormat(input_duration.to_string()));
            };
            match c {
                's' => duration = duration + Duration::seconds(number),
                'm' => duration = duration + Duration::minutes(number),
                'h' => duration = duration + Duration::hours(number),
                'd' => duration = duration + Duration::days(number),
                'w' => duration = duration + Duration::weeks(number),
                'M' => duration = duration + Duration::days(number * 30),
                'y' => duration = duration + Duration::days(number * 365),
                _ => return Err(ParseDurationError::InvalidDurationFormat(input_duration.to_string())),
            }
            current_number.clear();
        }   
    }

    Ok(duration)
}