use crate::config_loader::UserConfig;
use crate::platform;
use crate::report::Report;

pub fn run(report: &mut Report, user_config: Option<&UserConfig>) {
    platform::check_persistence(report, user_config);
}
