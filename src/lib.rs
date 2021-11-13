mod copypasted_impl;
pub use copypasted_impl::DrainFilter;

pub trait VecExt<T> {
    fn drain_filter<F>(&mut self, filter: F) -> DrainFilter<'_, T, F>
    where
        F: FnMut(&mut T) -> bool;
}

