use regex::Regex;
use std::collections::HashMap;
use std::str;
use url::form_urlencoded;

#[derive(Debug)]
pub enum FormValue {
    String(String),
    Array(Vec<String>),
}

impl FormValue {
    pub fn as_array(&self) -> Option<Vec<String>> {
        match self {
            FormValue::String(_) => None,
            FormValue::Array(array) => Some(array.to_vec()),
        }
    }

    pub fn as_string(&self) -> Option<String> {
        match self {
            FormValue::String(string) => Some(string.to_string()),
            FormValue::Array(_) => None,
        }
    }

    /* form_urlencoded::parse does not handle array data correctly, so we define our own
     * helper here.
     *
     * NOTE(jacob): This function takes some liberties with data validation -- in
     *      particular, undefined behavior includes:
     *          - mixed array and non-array values for a single variable
     *          - multiple occurances of the same variable
     *          - skipping array indices
     */
    pub fn parse_form_data(form_data: &[u8]) -> HashMap<String, FormValue> {
        // Parse everything into vectors for simplicity, and then do a final pass to convert
        // to the appropriate enum.
        let initial_vector_map: HashMap<String, Vec<Option<String>>> = HashMap::new();
        // TODO(jacob): figure out how to cache this
        let array_regex = Regex::new(r"(?P<name>.+)\[(?P<index>\d+)\]").unwrap();

        let vector_map = form_urlencoded::parse(form_data)
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .fold(
                initial_vector_map,
                |mut vector_map, (name, value)| {
                    let (var_name, index, mut new_vector) = array_regex.captures(&name)
                        .and_then(|captures| {
                            captures.name("name")
                                .map(|mat| mat.as_str())
                                .and_then(|var_name| {
                                    captures.name("index").map(|mat| (var_name, mat.as_str()))
                                }).and_then(|(var_name, index_str)| {
                                    str::parse::<usize>(index_str).ok()
                                        .map(|index| (var_name.to_string(), index))
                                })
                        }).map_or_else(
                            || {
                                let mut new_values = Vec::with_capacity(1);
                                new_values.resize(1, None);
                                (name, 0, new_values)
                            },
                            |(var_name, index)| {
                                let new_vector = vector_map.get(&var_name).map_or_else(
                                    || {
                                        let mut new_values = Vec::with_capacity(index + 1);
                                        new_values.resize(index + 1, None);
                                        new_values
                                    },
                                    |values| {
                                        let mut new_values = values.clone();
                                        if new_values.len() <= index {
                                            new_values.resize(index + 1, None);
                                        };
                                        new_values
                                    },
                                );
                                (var_name, index, new_vector)
                            },
                        );

                    new_vector[index] = Some(value);
                    vector_map.insert(var_name, new_vector);
                    vector_map
                }
            );

        vector_map.into_iter().flat_map(|(name, values)| {
            let flattened_values = values.into_iter().flat_map(|value_opt| value_opt).collect::<Vec<String>>();
            match &flattened_values[..] {
                [] => None,  // should never happen with well-formed input
                [single] => Some((name, FormValue::String(single.to_string()))),
                many => Some((name, FormValue::Array(many.to_vec()))),
            }
        }).collect()
    }
}
