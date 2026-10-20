//! Read bounds for the HCP tools, with a test-only override so the tests can
//! cross the bounds without writing thousands of records.

/// Rows fetched per `query_sql` page when enumerating a person's records.
const PAGE_SIZE: usize = 500;
/// Results returned per list, as ContextRouter's `maxSearchResults` default.
const SEARCH_RESULTS: usize = 100;

#[cfg(test)]
thread_local! {
    static OVERRIDE: std::cell::Cell<Option<(usize, usize)>> = const { std::cell::Cell::new(None) };
}

pub(super) fn page_size() -> usize {
    #[cfg(test)]
    if let Some((page, _)) = OVERRIDE.with(std::cell::Cell::get) {
        return page;
    }
    PAGE_SIZE
}

pub(super) fn search_results() -> usize {
    #[cfg(test)]
    if let Some((_, search)) = OVERRIDE.with(std::cell::Cell::get) {
        return search;
    }
    SEARCH_RESULTS
}

/// Lower both bounds for the current test thread until the guard drops.
#[cfg(test)]
pub(super) struct TestBounds;

#[cfg(test)]
impl TestBounds {
    pub(super) fn set(page: usize, search: usize) -> Self {
        OVERRIDE.with(|cell| cell.set(Some((page, search))));
        Self
    }
}

#[cfg(test)]
impl Drop for TestBounds {
    fn drop(&mut self) {
        OVERRIDE.with(|cell| cell.set(None));
    }
}
