use crate::platform;
use crate::report::Report;

pub fn run(report: &mut Report) {
    platform::check_persistence(report);
}
