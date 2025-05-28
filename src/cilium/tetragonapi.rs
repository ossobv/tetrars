// Hide a few doc spacing complaints.
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::doc_overindented_list_items)]
// Hide complaints about "TracingPolicyState" enums having "Tp" prefix.
#![allow(clippy::enum_variant_names)]
// Hide complaints about "pub enum Event" being 2+k
#![allow(clippy::large_enum_variant)]
// Import the generated file directly.
include!("tetragon.rs");
