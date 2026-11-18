//! "Did you mean" for misspelled names: a small edit distance, no deps.

/// Edit distance (insert, delete, substitute, swap two adjacent characters)
/// between two strings, by char: the optimal-string-alignment variant of
/// Damerau-Levenshtein, so the common typo `gmial` is one edit from `gmail`.
pub fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    d[a.len()][b.len()]
}

/// The candidate `input` most plausibly meant, if any is close enough.
///
/// Case is ignored. The input is compared with the whole candidate and with
/// the candidate's leading characters (at one extra edit), so an abbreviation
/// such as `guerrilla` or `gmial` still finds `guerrillamail` or
/// `gmail-alias`. The distance may be at most about a third of the input's
/// length (minimum 1).
pub fn closest<'a>(input: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let needle = input.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return None;
    }
    let n = needle.chars().count();
    let limit = (n.div_ceil(3)).max(1);
    candidates
        .into_iter()
        .filter_map(|c| {
            let lc = c.to_ascii_lowercase();
            let mut d = distance(&needle, &lc);
            if n >= 3 && lc.chars().count() > n {
                let head: String = lc.chars().take(n).collect();
                d = d.min(distance(&needle, &head) + 1);
            }
            (d <= limit).then_some((d, c))
        })
        .min_by_key(|&(d, c)| (d, c))
        .map(|(_, c)| c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distances() {
        assert_eq!(distance("", ""), 0);
        assert_eq!(distance("kitten", "sitting"), 3);
        assert_eq!(distance("mailtm", "mailtm"), 0);
        assert_eq!(distance("maitlm", "mailtm"), 1);
        assert_eq!(distance("gmial", "gmail"), 1);
    }

    #[test]
    fn suggests_close_names_only() {
        let names = ["mailtm", "guerrillamail", "tempmailorg", "duckmail"];
        assert_eq!(closest("mailt", names), Some("mailtm"));
        assert_eq!(closest("MailTM", names), Some("mailtm"));
        assert_eq!(closest("guerilamail", names), Some("guerrillamail"));
        assert_eq!(closest("guerrilla", names), Some("guerrillamail"));
        assert_eq!(closest("zzzzzz", names), None);
        assert_eq!(closest("", names), None);
    }

    #[test]
    fn suggests_kinds() {
        let kinds = ["gmail-alias", "outlook-alias", "own-domain", "edu"];
        assert_eq!(closest("gmail", kinds), Some("gmail-alias"));
        assert_eq!(closest("gmial-alias", kinds), Some("gmail-alias"));
        assert_eq!(closest("owndomain", kinds), Some("own-domain"));
        assert_eq!(closest("edo", kinds), Some("edu"));
        assert_eq!(closest("gmial", kinds), Some("gmail-alias"));
        assert_eq!(closest("own", kinds), Some("own-domain"));
        assert_eq!(closest("xyz", kinds), None);
    }
}
