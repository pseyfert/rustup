use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use anyhow::{anyhow, bail, Error, Result};
use clap::{Command as ClapCommand, AppSettings, Arg, ArgGroup, ArgMatches, ValueHint};
use clap_complete::{Shell, shells};

use super::help::*;
use super::self_update;
use super::term2;
use super::term2::Terminal;
use super::topical_doc;
use super::{
    common,
    self_update::{check_rustup_update, SelfUpdateMode},
};
use crate::cli::errors::CLIError;
use crate::dist::dist::{PartialTargetTriple, PartialToolchainDesc, Profile, TargetTriple};
use crate::dist::manifest::Component;
use crate::errors::RustupError;
use crate::process;
use crate::toolchain::{CustomToolchain, DistributableToolchain};
use crate::utils::utils;
use crate::Notification;
use crate::{command, Cfg, ComponentStatus, Toolchain};

fn handle_epipe(res: Result<utils::ExitCode>) -> Result<utils::ExitCode> {
    match res {
        Err(e) => {
            let root = e.root_cause();
            if let Some(io_err) = root.downcast_ref::<std::io::Error>() {
                if io_err.kind() == std::io::ErrorKind::BrokenPipe {
                    return Ok(utils::ExitCode(0));
                }
            }
            Err(e)
        }
        res => res,
    }
}

fn deprecated<F, B, R>(instead: &str, cfg: &mut Cfg, matches: B, callee: F) -> R
where
    F: FnOnce(&mut Cfg, B) -> R,
{
    (cfg.notify_handler)(Notification::PlainVerboseMessage(
        "Use of (currently) unmaintained command line interface.",
    ));
    (cfg.notify_handler)(Notification::PlainVerboseMessage(
        "The exact API of this command may change without warning",
    ));
    (cfg.notify_handler)(Notification::PlainVerboseMessage(
        "Eventually this command will be a true alias.  Until then:",
    ));
    (cfg.notify_handler)(Notification::PlainVerboseMessage(&format!(
        "  Please use `rustup {}` instead",
        instead
    )));
    callee(cfg, matches)
}

pub fn main() -> Result<utils::ExitCode> {
    self_update::cleanup_self_updater()?;

    use clap::ErrorKind::*;
    let matches = match cli().get_matches_from_safe(process().args_os()) {
        Ok(matches) => Ok(matches),
        Err(ce) => {
            match ce.kind() {
                HelpDisplayed => {
                    writeln!(process().stdout().lock(), "{}", ce.to_string())?;
                    return Ok(utils::ExitCode(0));
                },
                VersionDisplayed => {
                    writeln!(process().stdout().lock(), "{}", ce.to_string())?;
                    info!("This is the version for the rustup toolchain manager, not the rustc compiler.");

                    fn rustc_version() -> std::result::Result<String, Box<dyn std::error::Error>> {
                        let cfg = &mut common::set_globals(false, true)?;
                        let cwd = std::env::current_dir()?;

                        if let Some(t) = process().args().find(|x| x.starts_with('+')) {
                            debug!("Fetching rustc version from toolchain `{}`", t);
                            cfg.set_toolchain_override(&t[1..]);
                        }

                        let toolchain = cfg.find_or_install_override_toolchain_or_default(&cwd)?.0;

                        Ok(toolchain.rustc_version())
                    }

                    match rustc_version() {
                        Ok(version) => info!("The currently active `rustc` version is `{}`", version),
                        Err(err) => debug!("Wanted to tell you the current rustc version, too, but ran into this error: {}", err),
                    }
                    return Ok(utils::ExitCode(0));
                }
                _ => {
                    if [
                        InvalidSubcommand,
                        UnknownArgument,
                        DisplayHelpOnMissingArgumentOrSubcommand,
                    ]
                    .contains(&ce.kind())
                    {
                        writeln!(process().stdout().lock(), "{}", ce.to_string())?;
                        return Ok(utils::ExitCode(1));
                    }
                    Err(ce)
                }
            }
        }
    }?;
    let verbose = matches.is_present("verbose");
    let quiet = matches.is_present("quiet");
    let cfg = &mut common::set_globals(verbose, quiet)?;

    if let Some(t) = matches.value_of("+toolchain") {
        cfg.set_toolchain_override(&t[1..]);
    }

    if maybe_upgrade_data(cfg, &matches)? {
        return Ok(utils::ExitCode(0));
    }

    cfg.check_metadata_version()?;

    Ok(match matches.subcommand() {
        Some(("dump-testament", _)) => common::dump_testament()?,
        Some(("show", c)) => match c.subcommand() {
            Some(("active-toolchain", m)) => handle_epipe(show_active_toolchain(cfg, m))?,
            Some(("home", _)) => handle_epipe(show_rustup_home(cfg))?,
            Some(("profile", _)) => handle_epipe(show_profile(cfg))?,
            Some(("keys", _)) => handle_epipe(show_keys(cfg))?,
            _ => handle_epipe(show(cfg))?,
        },
        Some(("install", m)) => deprecated("toolchain install", cfg, m, update)?,
        Some(("update", m)) => update(cfg, m)?,
        Some(("check", _)) => check_updates(cfg)?,
        Some(("uninstall", m)) => deprecated("toolchain uninstall", cfg, m, toolchain_remove)?,
        Some(("default", m)) => default_(cfg, m)?,
        Some(("toolchain", c)) => match c.subcommand() {
            Some(("install", m)) => update(cfg, m)?,
            Some(("list", m)) => handle_epipe(toolchain_list(cfg, m))?,
            Some(("link", m)) => toolchain_link(cfg, m)?,
            Some(("uninstall", m)) => toolchain_remove(cfg, m)?,
            _ => unreachable!(),
        },
        Some(("target", c)) => match c.subcommand() {
            Some(("list", m)) => handle_epipe(target_list(cfg, m))?,
            Some(("add", m)) => target_add(cfg, m)?,
            Some(("remove", m)) => target_remove(cfg, m)?,
            _ => unreachable!(),
        },
        Some(("component", c)) => match c.subcommand() {
            Some(("list", m)) => handle_epipe(component_list(cfg, m))?,
            Some(("add", m)) => component_add(cfg, m)?,
            Some(("remove", m)) => component_remove(cfg, m)?,
            _ => unreachable!(),
        },
        Some(("override", c)) => match c.subcommand() {
            Some(("list", _)) => handle_epipe(common::list_overrides(cfg))?,
            Some(("set", m)) => override_add(cfg, m)?,
            Some(("unset", m)) => override_remove(cfg, m)?,
            _ => unreachable!(),
        },
        Some(("run", m)) => run(cfg, m)?,
        Some(("which", m)) => which(cfg, m)?,
        Some(("doc", m)) => doc(cfg, m)?,
        Some(("man", m)) => man(cfg, m)?,
        Some(("self", c)) => match c.subcommand() {
            Some(("update", _)) => self_update::update(cfg)?,
            Some(("uninstall", m)) => self_uninstall(m)?,
            _ => unreachable!(),
        },
        Some(("set", c)) => match c.subcommand() {
            Some(("default-host", m)) => set_default_host_triple(cfg, m)?,
            Some(("profile", m)) => set_profile(cfg, m)?,
            Some(("auto-self-update", m)) => set_auto_self_update(cfg, m)?,
            _ => unreachable!(),
        },
        Some(("completions", c)) => {
            if let Some(shell) = c.value_of("shell") {
                (output_completion_script(
                    shell.parse::<Shell>().unwrap(),
                    c.value_of("command")
                        .and_then(|cmd| cmd.parse::<CompletionCommand>().ok())
                        .unwrap_or(CompletionCommand::Rustup),
                ))?
            } else {
                unreachable!()
            }
        }
        _ => unreachable!(),
    })
}

pub(crate) fn cli() -> ClapCommand<'static> {
    let mut app = ClapCommand::new("rustup")
        .version(common::version())
        .about("The Rust toolchain installer")
        .after_help(RUSTUP_HELP)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg(
            Arg::new("verbose")
                .help("Enable verbose output")
                .short('v')
                .long("verbose"),
        )
        .arg(
            Arg::new("quiet")
                .conflicts_with("verbose")
                .help("Disable progress output")
                .short('q')
                .long("quiet"),
        )
        .arg(
            Arg::new("+toolchain")
                .help("release channel (e.g. +stable) or custom toolchain to set override")
                .validator(|s| {
                    if s.starts_with('+') {
                        Ok(())
                    } else {
                        Err("Toolchain overrides must begin with '+'".into())
                    }
                }),
        )
        .subcommand(
            ClapCommand::new("dump-testament")
                .about("Dump information about the build")
                .hide(true), // Not for users, only CI
        )
        .subcommand(
            ClapCommand::new("show")
                .about("Show the active and installed toolchains or profiles")
                .after_help(SHOW_HELP)
                .setting(AppSettings::VersionlessSubcommands)
                .setting(AppSettings::DeriveDisplayOrder)
                .subcommand(
                    ClapCommand::new("active-toolchain")
                        .about("Show the active toolchain")
                        .after_help(SHOW_ACTIVE_TOOLCHAIN_HELP)
                        .arg(
                            Arg::new("verbose")
                                .help("Enable verbose output with rustc information")
                                .takes_value(false)
                                .short('v')
                                .long("verbose"),
                        ),
                )
                .subcommand(
                    ClapCommand::new("home")
                        .about("Display the computed value of RUSTUP_HOME"),
                )
                .subcommand(ClapCommand::new("profile").about("Show the current profile"))
                .subcommand(ClapCommand::new("keys").about("Display the known PGP keys")),
        )
        .subcommand(
            ClapCommand::new("install")
                .about("Update Rust toolchains")
                .after_help(INSTALL_HELP)
                .hide(true) // synonym for 'toolchain install'
                .arg(
                    Arg::new("toolchain")
                        .help(TOOLCHAIN_ARG_HELP)
                        .required(true)
                        .multiple(true),
                )
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .takes_value(true)
                        .possible_values(Profile::names())
                        .required(false),
                )
                .arg(
                    Arg::new("no-self-update")
                        .help("Don't perform self-update when running the `rustup install` command")
                        .long("no-self-update")
                        .takes_value(false),
                )
                .arg(
                    Arg::new("force")
                        .help("Force an update, even if some components are missing")
                        .long("force")
                        .takes_value(false),
                ),
        )
        .subcommand(
            ClapCommand::new("uninstall")
                .about("Uninstall Rust toolchains")
                .hide(true) // synonym for 'toolchain uninstall'
                .arg(
                    Arg::new("toolchain")
                        .help(TOOLCHAIN_ARG_HELP)
                        .required(true)
                        .multiple(true),
                ),
        )
        .subcommand(
            ClapCommand::new("update")
                .about("Update Rust toolchains and rustup")
                .aliases(&["upgrade"])
                .after_help(UPDATE_HELP)
                .arg(
                    Arg::new("toolchain")
                        .help(TOOLCHAIN_ARG_HELP)
                        .required(false)
                        .multiple(true),
                )
                .arg(
                    Arg::new("no-self-update")
                        .help("Don't perform self update when running the `rustup update` command")
                        .long("no-self-update")
                        .takes_value(false),
                )
                .arg(
                    Arg::new("force")
                        .help("Force an update, even if some components are missing")
                        .long("force")
                        .takes_value(false),
                )
                .arg(
                    Arg::new("force-non-host")
                        .help("Install toolchains that require an emulator. See https://github.com/rust-lang/rustup/wiki/Non-host-toolchains")
                        .long("force-non-host")
                        .takes_value(false)),
        )
        .subcommand(ClapCommand::new("check").about("Check for updates to Rust toolchains and rustup"))
        .subcommand(
            ClapCommand::new("default")
                .about("Set the default toolchain")
                .after_help(DEFAULT_HELP)
                .arg(
                    Arg::new("toolchain")
                        .help(TOOLCHAIN_ARG_HELP)
                        .required(false),
                ),
        )
        .subcommand(
            ClapCommand::new("toolchain")
                .about("Modify or query the installed toolchains")
                .after_help(TOOLCHAIN_HELP)
                .setting(AppSettings::VersionlessSubcommands)
                .setting(AppSettings::DeriveDisplayOrder)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    ClapCommand::new("list")
                        .about("List installed toolchains")
                        .arg(
                            Arg::new("verbose")
                                .help("Enable verbose output with toolchain information")
                                .takes_value(false)
                                .short('v')
                                .long("verbose"),
                        ),
                )
                .subcommand(
                    ClapCommand::new("install")
                        .about("Install or update a given toolchain")
                        .aliases(&["update", "add"])
                        .arg(
                            Arg::new("toolchain")
                                .help(TOOLCHAIN_ARG_HELP)
                                .required(true)
                                .multiple(true),
                        )
                        .arg(
                            Arg::new("profile")
                                .long("profile")
                                .takes_value(true)
                                .possible_values(Profile::names())
                                .required(false),
                        )
                        .arg(
                            Arg::new("no-self-update")
                                .help(
                                    "Don't perform self update when running the\
                                     `rustup toolchain install` command",
                                )
                                .long("no-self-update")
                                .takes_value(false),
                        )
                        .arg(
                            Arg::new("components")
                                .help("Add specific components on installation")
                                .long("component")
                                .short('c')
                                .takes_value(true)
                                .multiple(true)
                                .use_value_delimiter(true),
                        )
                        .arg(
                            Arg::new("targets")
                                .help("Add specific targets on installation")
                                .long("target")
                                .short('t')
                                .takes_value(true)
                                .multiple(true)
                                .use_value_delimiter(true),
                        )
                        .arg(
                            Arg::new("force")
                                .help("Force an update, even if some components are missing")
                                .long("force")
                                .takes_value(false),
                        )
                        .arg(
                            Arg::new("allow-downgrade")
                                .help("Allow rustup to downgrade the toolchain to satisfy your component choice")
                                .long("allow-downgrade")
                                .takes_value(false),
                        ),
                )
                .subcommand(
                    ClapCommand::new("uninstall")
                        .about("Uninstall a toolchain")
                        .alias("remove")
                        .arg(
                            Arg::new("toolchain")
                                .help(TOOLCHAIN_ARG_HELP)
                                .required(true)
                                .multiple(true),
                        ),
                )
                .subcommand(
                    ClapCommand::new("link")
                        .about("Create a custom toolchain by symlinking to a directory")
                        .after_help(TOOLCHAIN_LINK_HELP)
                        .arg(
                            Arg::new("toolchain")
                                .help("Custom toolchain name")
                                .required(true),
                        )
                        .arg(
                            Arg::new("path")
                                .help("Path to the directory")
                                .required(true),
                        ),
                ),
        )
        .subcommand(
            ClapCommand::new("target")
                .about("Modify a toolchain's supported targets")
                .setting(AppSettings::VersionlessSubcommands)
                .setting(AppSettings::DeriveDisplayOrder)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    ClapCommand::new("list")
                        .about("List installed and available targets")
                        .arg(
                            Arg::new("installed")
                                .long("--installed")
                                .help("List only installed targets"),
                        )
                        .arg(
                            Arg::new("toolchain")
                                .help(TOOLCHAIN_ARG_HELP)
                                .long("toolchain")
                                .takes_value(true),
                        ),
                )
                .subcommand(
                    ClapCommand::new("add")
                        .about("Add a target to a Rust toolchain")
                        .alias("install")
                        .arg(Arg::new("target").required(true).multiple(true).help(
                            "List of targets to install; \
                             \"all\" installs all available targets",
                        ))
                        .arg(
                            Arg::new("toolchain")
                                .help(TOOLCHAIN_ARG_HELP)
                                .long("toolchain")
                                .takes_value(true),
                        ),
                )
                .subcommand(
                    ClapCommand::new("remove")
                        .about("Remove a target from a Rust toolchain")
                        .alias("uninstall")
                        .arg(Arg::new("target").required(true).multiple(true))
                        .arg(
                            Arg::new("toolchain")
                                .help(TOOLCHAIN_ARG_HELP)
                                .long("toolchain")
                                .takes_value(true),
                        ),
                ),
        )
        .subcommand(
            ClapCommand::new("component")
                .about("Modify a toolchain's installed components")
                .setting(AppSettings::VersionlessSubcommands)
                .setting(AppSettings::DeriveDisplayOrder)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    ClapCommand::new("list")
                        .about("List installed and available components")
                        .arg(
                            Arg::new("installed")
                                .long("--installed")
                                .help("List only installed components"),
                        )
                        .arg(
                            Arg::new("toolchain")
                                .help(TOOLCHAIN_ARG_HELP)
                                .long("toolchain")
                                .takes_value(true),
                        ),
                )
                .subcommand(
                    ClapCommand::new("add")
                        .about("Add a component to a Rust toolchain")
                        .arg(Arg::new("component").required(true).multiple(true))
                        .arg(
                            Arg::new("toolchain")
                                .help(TOOLCHAIN_ARG_HELP)
                                .long("toolchain")
                                .takes_value(true),
                        )
                        .arg(Arg::new("target").long("target").takes_value(true)),
                )
                .subcommand(
                    ClapCommand::new("remove")
                        .about("Remove a component from a Rust toolchain")
                        .arg(Arg::new("component").required(true).multiple(true))
                        .arg(
                            Arg::new("toolchain")
                                .help(TOOLCHAIN_ARG_HELP)
                                .long("toolchain")
                                .takes_value(true),
                        )
                        .arg(Arg::new("target").long("target").takes_value(true)),
                ),
        )
        .subcommand(
            ClapCommand::new("override")
                .about("Modify directory toolchain overrides")
                .after_help(OVERRIDE_HELP)
                .setting(AppSettings::VersionlessSubcommands)
                .setting(AppSettings::DeriveDisplayOrder)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    ClapCommand::new("list").about("List directory toolchain overrides"),
                )
                .subcommand(
                    ClapCommand::new("set")
                        .about("Set the override toolchain for a directory")
                        .alias("add")
                        .arg(
                            Arg::new("toolchain")
                                .help(TOOLCHAIN_ARG_HELP)
                                .required(true),
                        )
                        .arg(
                            Arg::new("path")
                                .long("path")
                                .takes_value(true)
                                .help("Path to the directory"),
                        ),
                )
                .subcommand(
                    ClapCommand::new("unset")
                        .about("Remove the override toolchain for a directory")
                        .after_help(OVERRIDE_UNSET_HELP)
                        .alias("remove")
                        .arg(
                            Arg::new("path")
                                .long("path")
                                .takes_value(true)
                                .help("Path to the directory"),
                        )
                        .arg(
                            Arg::new("nonexistent")
                                .long("nonexistent")
                                .takes_value(false)
                                .help("Remove override toolchain for all nonexistent directories"),
                        ),
                ),
        )
        .subcommand(
            ClapCommand::new("run")
                .about("Run a command with an environment configured for a given toolchain")
                .after_help(RUN_HELP)
                .setting(AppSettings::TrailingVarArg)
                .arg(
                    Arg::new("install")
                        .help("Install the requested toolchain if needed")
                        .long("install"),
                )
                .arg(
                    Arg::new("toolchain")
                        .help(TOOLCHAIN_ARG_HELP)
                        .required(true),
                )
                .arg(
                    Arg::new("command")
                        .required(true)
                        .multiple(true)
                        .value_hint(ValueHint::CommandWithArguments)
                        .use_value_delimiter(false),
                ),
        )
        .subcommand(
            ClapCommand::new("which")
                .about("Display which binary will be run for a given command")
                .arg(Arg::new("command").required(true))
                .arg(
                    Arg::new("toolchain")
                        .help(TOOLCHAIN_ARG_HELP)
                        .long("toolchain")
                        .takes_value(true),
                ),
        )
        .subcommand(
            ClapCommand::new("doc")
                .alias("docs")
                .about("Open the documentation for the current toolchain")
                .after_help(DOC_HELP)
                .arg(
                    Arg::new("path")
                        .long("path")
                        .help("Only print the path to the documentation"),
                )
                .args(
                    &DOCS_DATA
                        .iter()
                        .map(|(name, help_msg, _)| Arg::new(name).long(name).help(help_msg))
                        .collect::<Vec<_>>(),
                )
                .arg(
                    Arg::new("toolchain")
                        .help(TOOLCHAIN_ARG_HELP)
                        .long("toolchain")
                        .takes_value(true),
                )
                .group(
                    ArgGroup::with_name("page").args(
                        &DOCS_DATA
                            .iter()
                            .map(|(name, _, _)| *name)
                            .collect::<Vec<_>>(),
                    ),
                )
                .arg(Arg::new("topic").help(TOPIC_ARG_HELP)),
        );

    if cfg!(not(target_os = "windows")) {
        app = app.subcommand(
            ClapCommand::new("man")
                .about("View the man page for a given command")
                .arg(Arg::new("command").required(true))
                .arg(
                    Arg::new("toolchain")
                        .help(TOOLCHAIN_ARG_HELP)
                        .long("toolchain")
                        .takes_value(true),
                ),
        );
    }

    app = app
        .subcommand(
            ClapCommand::new("self")
                .about("Modify the rustup installation")
                .setting(AppSettings::VersionlessSubcommands)
                .setting(AppSettings::DeriveDisplayOrder)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    ClapCommand::new("update").about("Download and install updates to rustup"),
                )
                .subcommand(
                    ClapCommand::new("uninstall")
                        .about("Uninstall rustup.")
                        .arg(Arg::new("no-prompt").short('y')),
                )
                .subcommand(
                    ClapCommand::new("upgrade-data")
                        .about("Upgrade the internal data format."),
                ),
        )
        .subcommand(
            ClapCommand::new("set")
                .about("Alter rustup settings")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    ClapCommand::new("default-host")
                        .about("The triple used to identify toolchains when not specified")
                        .arg(Arg::new("host_triple").required(true)),
                )
                .subcommand(
                    ClapCommand::new("profile")
                        .about("The default components installed")
                        .arg(
                            Arg::new("profile-name")
                                .required(true)
                                .possible_values(Profile::names())
                                .default_value(Profile::default_name()),
                        ),
                )
                .subcommand(
                    ClapCommand::new("auto-self-update")
                        .about("The rustup auto self update mode")
                        .arg(
                            Arg::new("auto-self-update-mode")
                                .required(true)
                                .possible_values(SelfUpdateMode::modes())
                                .default_value(SelfUpdateMode::default_mode()),
                        ),
                ),
        );

    // Clap provides no good way to say that help should be printed in all
    // cases where an argument without a default is not provided. The following
    // creates lists out all the conditions where the "shell" argument are
    // provided and give the default of "rustup". This way if "shell" is not
    // provided then the help will still be printed.
    let completion_defaults = Shell::variants()
        .iter()
        .map(|&shell| ("shell", Some(shell), "rustup"))
        .collect::<Vec<_>>();

    app.subcommand(
        ClapCommand::new("completions")
            .about("Generate tab-completion scripts for your shell")
            .after_help(COMPLETIONS_HELP)
            .setting(AppSettings::ArgRequiredElseHelp)
            .arg(Arg::new("shell").possible_values(&Shell::variants()))
            .arg(
                Arg::new("command")
                    .possible_values(&CompletionCommand::variants())
                    .default_value_ifs(&completion_defaults[..]),
            ),
    )
}

fn maybe_upgrade_data(cfg: &Cfg, m: &ArgMatches) -> Result<bool> {
    match m.subcommand() {
        Some(("self", c)) => match c.subcommand() {
            Some(("upgrade-data", _)) => {
                cfg.upgrade_data()?;
                Ok(true)
            }
            _ => Ok(false),
        },
        _ => Ok(false),
    }
}

fn update_bare_triple_check(cfg: &Cfg, name: &str) -> Result<()> {
    if let Some(triple) = PartialTargetTriple::new(name) {
        warn!("(partial) target triple specified instead of toolchain name");
        let installed_toolchains = cfg.list_toolchains()?;
        let default = cfg.find_default()?;
        let default_name = default.map(|t| t.name().to_string()).unwrap_or_default();
        let mut candidates = vec![];
        for t in installed_toolchains {
            if t == default_name {
                continue;
            }
            if let Ok(desc) = PartialToolchainDesc::from_str(&t) {
                fn triple_comp_eq(given: &str, from_desc: Option<&String>) -> bool {
                    from_desc.map_or(false, |s| *s == *given)
                }

                let triple_matches = triple
                    .arch
                    .as_ref()
                    .map_or(true, |s| triple_comp_eq(s, desc.target.arch.as_ref()))
                    && triple
                        .os
                        .as_ref()
                        .map_or(true, |s| triple_comp_eq(s, desc.target.os.as_ref()))
                    && triple
                        .env
                        .as_ref()
                        .map_or(true, |s| triple_comp_eq(s, desc.target.env.as_ref()));
                if triple_matches {
                    candidates.push(t);
                }
            }
        }
        match candidates.len() {
            0 => err!("no candidate toolchains found"),
            1 => writeln!(
                process().stdout(),
                "\nyou may use the following toolchain: {}\n",
                candidates[0]
            )?,
            _ => {
                writeln!(
                    process().stdout(),
                    "\nyou may use one of the following toolchains:"
                )?;
                for n in &candidates {
                    writeln!(process().stdout(), "{}", n)?;
                }
                writeln!(process().stdout(),)?;
            }
        }
        bail!(RustupError::ToolchainNotInstalled(name.to_string()));
    }
    Ok(())
}

fn default_bare_triple_check(cfg: &Cfg, name: &str) -> Result<()> {
    if let Some(triple) = PartialTargetTriple::new(name) {
        warn!("(partial) target triple specified instead of toolchain name");
        let default = cfg.find_default()?;
        let default_name = default.map(|t| t.name().to_string()).unwrap_or_default();
        if let Ok(mut desc) = PartialToolchainDesc::from_str(&default_name) {
            desc.target = triple;
            let maybe_toolchain = format!("{}", desc);
            let toolchain = cfg.get_toolchain(maybe_toolchain.as_ref(), false)?;
            if toolchain.name() == default_name {
                warn!(
                    "(partial) triple '{}' resolves to a toolchain that is already default",
                    name
                );
            } else {
                writeln!(
                    process().stdout(),
                    "\nyou may use the following toolchain: {}\n",
                    toolchain.name()
                )?;
            }
            return Err(RustupError::ToolchainNotInstalled(name.to_string()).into());
        }
    }
    Ok(())
}

fn default_(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    if m.is_present("toolchain") {
        let toolchain = m.value_of("toolchain").unwrap();
        default_bare_triple_check(cfg, toolchain)?;
        let toolchain = cfg.get_toolchain(toolchain, false)?;

        let status = if !toolchain.is_custom() {
            let distributable = DistributableToolchain::new(&toolchain)?;
            Some(distributable.install_from_dist_if_not_installed()?)
        } else if !toolchain.exists() && toolchain.name() != "none" {
            return Err(RustupError::ToolchainNotInstalled(toolchain.name().to_string()).into());
        } else {
            None
        };

        toolchain.make_default()?;

        if let Some(status) = status {
            writeln!(process().stdout())?;
            common::show_channel_update(cfg, toolchain.name(), Ok(status))?;
        }

        let cwd = utils::current_dir()?;
        if let Some((toolchain, reason)) = cfg.find_override(&cwd)? {
            info!(
                "note that the toolchain '{}' is currently in use ({})",
                toolchain.name(),
                reason
            );
        }
    } else {
        let default_toolchain: Result<String> = cfg
            .get_default()?
            .ok_or_else(|| anyhow!("no default toolchain configured"));
        writeln!(process().stdout(), "{} (default)", default_toolchain?)?;
    }

    Ok(utils::ExitCode(0))
}

fn check_updates(cfg: &Cfg) -> Result<utils::ExitCode> {
    let mut t = term2::stdout();
    let channels = cfg.list_channels()?;

    for channel in channels {
        match channel {
            (ref name, Ok(ref toolchain)) => {
                let distributable = DistributableToolchain::new(toolchain)?;
                let current_version = distributable.show_version()?;
                let dist_version = distributable.show_dist_version()?;
                let _ = t.attr(term2::Attr::Bold);
                write!(t, "{} - ", name)?;
                match (current_version, dist_version) {
                    (None, None) => {
                        let _ = t.fg(term2::color::RED);
                        writeln!(t, "Cannot identify installed or update versions")?;
                    }
                    (Some(cv), None) => {
                        let _ = t.fg(term2::color::GREEN);
                        write!(t, "Up to date")?;
                        let _ = t.reset();
                        writeln!(t, " : {}", cv)?;
                    }
                    (Some(cv), Some(dv)) => {
                        let _ = t.fg(term2::color::YELLOW);
                        write!(t, "Update available")?;
                        let _ = t.reset();
                        writeln!(t, " : {} -> {}", cv, dv)?;
                    }
                    (None, Some(dv)) => {
                        let _ = t.fg(term2::color::YELLOW);
                        write!(t, "Update available")?;
                        let _ = t.reset();
                        writeln!(t, " : (Unknown version) -> {}", dv)?;
                    }
                }
            }
            (_, Err(err)) => return Err(err),
        }
    }

    check_rustup_update()?;

    Ok(utils::ExitCode(0))
}

fn update(cfg: &mut Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let self_update_mode = cfg.get_self_update_mode()?;
    // Priority: no-self-update feature > self_update_mode > no-self-update args.
    // Update only if rustup does **not** have the no-self-update feature,
    // and auto-self-update is configured to **enable**
    // and has **no** no-self-update parameter.
    let self_update = !self_update::NEVER_SELF_UPDATE
        && self_update_mode == SelfUpdateMode::Enable
        && !m.is_present("no-self-update");
    let forced = m.is_present("force-non-host");
    if let Some(p) = m.value_of("profile") {
        let p = Profile::from_str(p)?;
        cfg.set_profile_override(p);
    }
    let cfg = &cfg;
    if cfg.get_profile()? == Profile::Complete {
        warn!("{}", common::WARN_COMPLETE_PROFILE);
    }
    if let Some(names) = m.values_of("toolchain") {
        for name in names {
            update_bare_triple_check(cfg, name)?;

            let toolchain_has_triple = match PartialToolchainDesc::from_str(name) {
                Ok(x) => x.has_triple(),
                _ => false,
            };

            if toolchain_has_triple {
                let host_arch = TargetTriple::from_host_or_build();
                if let Ok(partial_toolchain_desc) = PartialToolchainDesc::from_str(name) {
                    let target_triple = partial_toolchain_desc.resolve(&host_arch)?.target;
                    if !forced && !host_arch.can_run(&target_triple)? {
                        err!("DEPRECATED: future versions of rustup will require --force-non-host to install a non-host toolchain as the default.");
                        warn!(
                            "toolchain '{}' may not be able to run on this system.",
                            name
                        );
                        warn!(
                            "If you meant to build software to target that platform, perhaps try `rustup target add {}` instead?",
                            target_triple.to_string()
                        );
                    }
                }
            }

            let toolchain = cfg.get_toolchain(name, false)?;

            let status = if !toolchain.is_custom() {
                let components: Vec<_> = m
                    .values_of("components")
                    .map(|v| v.collect())
                    .unwrap_or_else(Vec::new);
                let targets: Vec<_> = m
                    .values_of("targets")
                    .map(|v| v.collect())
                    .unwrap_or_else(Vec::new);
                let distributable = DistributableToolchain::new(&toolchain)?;
                Some(distributable.install_from_dist(
                    m.is_present("force"),
                    m.is_present("allow-downgrade"),
                    &components,
                    &targets,
                    None,
                )?)
            } else if !toolchain.exists() {
                bail!(RustupError::InvalidToolchainName(
                    toolchain.name().to_string()
                ));
            } else {
                None
            };

            if let Some(status) = status.clone() {
                writeln!(process().stdout())?;
                common::show_channel_update(cfg, toolchain.name(), Ok(status))?;
            }

            if cfg.get_default()?.is_none() {
                use crate::UpdateStatus;
                if let Some(UpdateStatus::Installed) = status {
                    toolchain.make_default()?;
                }
            }
        }
        if self_update {
            common::self_update(|| Ok(utils::ExitCode(0)))?;
        }
    } else {
        common::update_all_channels(cfg, self_update, m.is_present("force"))?;
        info!("cleaning up downloads & tmp directories");
        utils::delete_dir_contents(&cfg.download_dir);
        cfg.temp_cfg.clean();
    }

    if !self_update::NEVER_SELF_UPDATE && self_update_mode == SelfUpdateMode::CheckOnly {
        check_rustup_update()?;
    }

    if self_update::NEVER_SELF_UPDATE {
        info!("self-update is disabled for this build of rustup");
        info!("any updates to rustup will need to be fetched with your system package manager")
    }

    Ok(utils::ExitCode(0))
}

fn run(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let toolchain = m.value_of("toolchain").unwrap();
    let args = m.values_of("command").unwrap();
    let args: Vec<_> = args.collect();
    let cmd = cfg.create_command_for_toolchain(toolchain, m.is_present("install"), args[0])?;

    let code = command::run_command_for_dir(cmd, args[0], &args[1..])?;
    Ok(code)
}

fn which(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let binary = m.value_of("command").unwrap();
    let binary_path = if m.is_present("toolchain") {
        let toolchain = m.value_of("toolchain").unwrap();
        cfg.which_binary_by_toolchain(toolchain, binary)?
    } else {
        cfg.which_binary(&utils::current_dir()?, binary)?
    };

    utils::assert_is_file(&binary_path)?;

    writeln!(process().stdout(), "{}", binary_path.display())?;
    Ok(utils::ExitCode(0))
}

fn show(cfg: &Cfg) -> Result<utils::ExitCode> {
    // Print host triple
    {
        let mut t = term2::stdout();
        t.attr(term2::Attr::Bold)?;
        write!(t, "Default host: ")?;
        t.reset()?;
        writeln!(t, "{}", cfg.get_default_host_triple()?)?;
    }

    // Print rustup home directory
    {
        let mut t = term2::stdout();
        t.attr(term2::Attr::Bold)?;
        write!(t, "rustup home:  ")?;
        t.reset()?;
        writeln!(t, "{}", cfg.rustup_dir.display())?;
        writeln!(t)?;
    }

    let cwd = utils::current_dir()?;
    let installed_toolchains = cfg.list_toolchains()?;
    // XXX: we may want a find_without_install capability for show.
    let active_toolchain = cfg.find_or_install_override_toolchain_or_default(&cwd);

    // active_toolchain will carry the reason we don't have one in its detail.
    let active_targets = if let Ok(ref at) = active_toolchain {
        if let Ok(distributable) = DistributableToolchain::new(&at.0) {
            match distributable.list_components() {
                Ok(cs_vec) => cs_vec
                    .into_iter()
                    .filter(|c| c.component.short_name_in_manifest() == "rust-std")
                    .filter(|c| c.installed)
                    .collect(),
                Err(_) => vec![],
            }
        } else {
            // These three vec![] could perhaps be reduced with and_then on active_toolchain.
            vec![]
        }
    } else {
        vec![]
    };

    let show_installed_toolchains = installed_toolchains.len() > 1;
    let show_active_targets = active_targets.len() > 1;
    let show_active_toolchain = true;

    // Only need to display headers if we have multiple sections
    let show_headers = [
        show_installed_toolchains,
        show_active_targets,
        show_active_toolchain,
    ]
    .iter()
    .filter(|x| **x)
    .count()
        > 1;

    if show_installed_toolchains {
        let mut t = term2::stdout();
        if show_headers {
            print_header::<Error>(&mut t, "installed toolchains")?;
        }
        let default_name: Result<String> = cfg
            .get_default()?
            .ok_or_else(|| anyhow!("no default toolchain configured"));
        let default_name = default_name?;
        for it in installed_toolchains {
            if default_name == it {
                writeln!(t, "{} (default)", it)?;
            } else {
                writeln!(t, "{}", it)?;
            }
        }
        if show_headers {
            writeln!(t)?
        };
    }

    if show_active_targets {
        let mut t = term2::stdout();
        if show_headers {
            print_header::<Error>(&mut t, "installed targets for active toolchain")?;
        }
        for at in active_targets {
            writeln!(
                t,
                "{}",
                at.component
                    .target
                    .as_ref()
                    .expect("rust-std should have a target")
            )?;
        }
        if show_headers {
            writeln!(t)?;
        };
    }

    if show_active_toolchain {
        let mut t = term2::stdout();
        if show_headers {
            print_header::<Error>(&mut t, "active toolchain")?;
        }

        match active_toolchain {
            Ok(atc) => match atc {
                (ref toolchain, Some(ref reason)) => {
                    writeln!(t, "{} ({})", toolchain.name(), reason)?;
                    writeln!(t, "{}", toolchain.rustc_version())?;
                }
                (ref toolchain, None) => {
                    writeln!(t, "{} (default)", toolchain.name())?;
                    writeln!(t, "{}", toolchain.rustc_version())?;
                }
            },
            Err(err) => {
                let root_cause = err.root_cause();
                if let Some(RustupError::ToolchainNotSelected) =
                    root_cause.downcast_ref::<RustupError>()
                {
                    writeln!(t, "no active toolchain")?;
                } else if let Some(cause) = err.source() {
                    writeln!(t, "(error: {}, {})", err, cause)?;
                } else {
                    writeln!(t, "(error: {})", err)?;
                }
            }
        }

        if show_headers {
            writeln!(t)?
        }
    }

    fn print_header<E>(t: &mut term2::StdoutTerminal, s: &str) -> std::result::Result<(), E>
    where
        E: From<term::Error> + From<std::io::Error>,
    {
        t.attr(term2::Attr::Bold)?;
        writeln!(t, "{}", s)?;
        writeln!(t, "{}", "-".repeat(s.len()))?;
        writeln!(t)?;
        t.reset()?;
        Ok(())
    }

    Ok(utils::ExitCode(0))
}

fn show_active_toolchain(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let verbose = m.is_present("verbose");
    let cwd = utils::current_dir()?;
    match cfg.find_or_install_override_toolchain_or_default(&cwd) {
        Err(e) => {
            let root_cause = e.root_cause();
            if let Some(RustupError::ToolchainNotSelected) =
                root_cause.downcast_ref::<RustupError>()
            {
            } else {
                return Err(e);
            }
        }
        Ok((toolchain, reason)) => {
            if let Some(reason) = reason {
                writeln!(process().stdout(), "{} ({})", toolchain.name(), reason)?;
            } else {
                writeln!(process().stdout(), "{} (default)", toolchain.name())?;
            }
            if verbose {
                writeln!(process().stdout(), "{}", toolchain.rustc_version())?;
            }
        }
    }
    Ok(utils::ExitCode(0))
}

fn show_rustup_home(cfg: &Cfg) -> Result<utils::ExitCode> {
    writeln!(process().stdout(), "{}", cfg.rustup_dir.display())?;
    Ok(utils::ExitCode(0))
}

fn target_list(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let toolchain = explicit_or_dir_toolchain(cfg, m)?;

    if m.is_present("installed") {
        common::list_installed_targets(&toolchain)
    } else {
        common::list_targets(&toolchain)
    }
}

fn target_add(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let toolchain = explicit_or_dir_toolchain(cfg, m)?;
    // XXX: long term move this error to cli ? the normal .into doesn't work
    // because Result here is the wrong sort and expression type ascription
    // isn't a feature yet.
    // list_components *and* add_component would both be inappropriate for
    // custom toolchains.
    let distributable = DistributableToolchain::new_for_components(&toolchain)?;

    let mut targets: Vec<String> = m
        .values_of("target")
        .unwrap()
        .map(ToString::to_string)
        .collect();

    if targets.contains(&"all".to_string()) {
        if targets.len() != 1 {
            return Err(anyhow!(
                "`rustup target add {}` includes `all`",
                targets.join(" ")
            ));
        }

        targets.clear();
        for component in distributable.list_components()? {
            if component.component.short_name_in_manifest() == "rust-std"
                && component.available
                && !component.installed
            {
                let target = component
                    .component
                    .target
                    .as_ref()
                    .expect("rust-std should have a target");
                targets.push(target.to_string());
            }
        }
    }

    for target in &targets {
        let new_component = Component::new(
            "rust-std".to_string(),
            Some(TargetTriple::new(target)),
            false,
        );
        distributable.add_component(new_component)?;
    }

    Ok(utils::ExitCode(0))
}

fn target_remove(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let toolchain = explicit_or_dir_toolchain(cfg, m)?;

    for target in m.values_of("target").unwrap() {
        let new_component = Component::new(
            "rust-std".to_string(),
            Some(TargetTriple::new(target)),
            false,
        );
        let distributable = DistributableToolchain::new_for_components(&toolchain)?;
        distributable.remove_component(new_component)?;
    }

    Ok(utils::ExitCode(0))
}

fn component_list(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let toolchain = explicit_or_dir_toolchain(cfg, m)?;

    if m.is_present("installed") {
        common::list_installed_components(&toolchain)
    } else {
        common::list_components(&toolchain)?;
        Ok(utils::ExitCode(0))
    }
}

fn component_add(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let toolchain = explicit_or_dir_toolchain(cfg, m)?;
    let distributable = DistributableToolchain::new(&toolchain)?;
    let target = m.value_of("target").map(TargetTriple::new).or_else(|| {
        distributable
            .desc()
            .as_ref()
            .ok()
            .map(|desc| desc.target.clone())
    });

    for component in m.values_of("component").unwrap() {
        let new_component = Component::new_with_target(component, false)
            .unwrap_or_else(|| Component::new(component.to_string(), target.clone(), true));
        distributable.add_component(new_component)?;
    }

    Ok(utils::ExitCode(0))
}

fn component_remove(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let toolchain = explicit_or_dir_toolchain(cfg, m)?;
    let distributable = DistributableToolchain::new_for_components(&toolchain)?;
    let target = m.value_of("target").map(TargetTriple::new).or_else(|| {
        distributable
            .desc()
            .as_ref()
            .ok()
            .map(|desc| desc.target.clone())
    });

    for component in m.values_of("component").unwrap() {
        let new_component = Component::new_with_target(component, false)
            .unwrap_or_else(|| Component::new(component.to_string(), target.clone(), true));
        distributable.remove_component(new_component)?;
    }

    Ok(utils::ExitCode(0))
}

fn explicit_or_dir_toolchain<'a>(cfg: &'a Cfg, m: &ArgMatches) -> Result<Toolchain<'a>> {
    let toolchain = m.value_of("toolchain");
    if let Some(toolchain) = toolchain {
        let toolchain = cfg.get_toolchain(toolchain, false)?;
        return Ok(toolchain);
    }

    let cwd = utils::current_dir()?;
    let (toolchain, _) = cfg.toolchain_for_dir(&cwd)?;

    Ok(toolchain)
}

fn toolchain_list(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    common::list_toolchains(cfg, m.is_present("verbose"))
}

fn toolchain_link(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let toolchain = m.value_of("toolchain").unwrap();
    let path = m.value_of("path").unwrap();
    let toolchain = cfg.get_toolchain(toolchain, true)?;

    if let Ok(custom) = CustomToolchain::new(&toolchain) {
        custom.install_from_dir(Path::new(path), true)?;
        Ok(utils::ExitCode(0))
    } else {
        Err(anyhow!(
            "invalid custom toolchain name: '{}'",
            toolchain.name().to_string()
        ))
    }
}

fn toolchain_remove(cfg: &mut Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    for toolchain in m.values_of("toolchain").unwrap() {
        let toolchain = cfg.get_toolchain(toolchain, false)?;
        toolchain.remove()?;
    }
    Ok(utils::ExitCode(0))
}

fn override_add(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let toolchain = m.value_of("toolchain").unwrap();
    let toolchain = cfg.get_toolchain(toolchain, false)?;

    let status = if !toolchain.is_custom() {
        let distributable = DistributableToolchain::new(&toolchain)?;
        Some(distributable.install_from_dist_if_not_installed()?)
    } else if !toolchain.exists() {
        return Err(RustupError::ToolchainNotInstalled(toolchain.name().to_string()).into());
    } else {
        None
    };

    let path = if let Some(path) = m.value_of("path") {
        PathBuf::from(path)
    } else {
        utils::current_dir()?
    };
    toolchain.make_override(&path)?;

    if let Some(status) = status {
        writeln!(process().stdout(),)?;
        common::show_channel_update(cfg, toolchain.name(), Ok(status))?;
    }

    Ok(utils::ExitCode(0))
}

fn override_remove(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let paths = if m.is_present("nonexistent") {
        let list: Vec<_> = cfg.settings_file.with(|s| {
            Ok(s.overrides
                .iter()
                .filter_map(|(k, _)| {
                    if Path::new(k).is_dir() {
                        None
                    } else {
                        Some(k.clone())
                    }
                })
                .collect())
        })?;
        if list.is_empty() {
            info!("no nonexistent paths detected");
        }
        list
    } else if m.is_present("path") {
        vec![m.value_of("path").unwrap().to_string()]
    } else {
        vec![utils::current_dir()?.to_str().unwrap().to_string()]
    };

    for path in paths {
        if cfg
            .settings_file
            .with_mut(|s| Ok(s.remove_override(Path::new(&path), cfg.notify_handler.as_ref())))?
        {
            info!("override toolchain for '{}' removed", path);
        } else {
            info!("no override toolchain for '{}'", path);
            if !m.is_present("path") && !m.is_present("nonexistent") {
                info!(
                    "you may use `--path <path>` option to remove override toolchain \
                     for a specific path"
                );
            }
        }
    }
    Ok(utils::ExitCode(0))
}

const DOCS_DATA: &[(&str, &str, &str,)] = &[
    // flags can be used to open specific documents, e.g. `rustup doc --nomicon`
    // tuple elements: document name used as flag, help message, document index path
    ("alloc", "The Rust core allocation and collections library", "alloc/index.html"),
    ("book", "The Rust Programming Language book", "book/index.html"),
    ("cargo", "The Cargo Book", "cargo/index.html"),
    ("core", "The Rust Core Library", "core/index.html"),
    ("edition-guide", "The Rust Edition Guide", "edition-guide/index.html"),
    ("nomicon", "The Dark Arts of Advanced and Unsafe Rust Programming", "nomicon/index.html"),
    ("proc_macro", "A support library for macro authors when defining new macros", "proc_macro/index.html"),
    ("reference", "The Rust Reference", "reference/index.html"),
    ("rust-by-example", "A collection of runnable examples that illustrate various Rust concepts and standard libraries", "rust-by-example/index.html"),
    ("rustc", "The compiler for the Rust programming language", "rustc/index.html"),
    ("rustdoc", "Generate documentation for Rust projects", "rustdoc/index.html"),
    ("std", "Standard library API documentation", "std/index.html"),
    ("test", "Support code for rustc's built in unit-test and micro-benchmarking framework", "test/index.html"),
    ("unstable-book", "The Unstable Book", "unstable-book/index.html"),
    ("embedded-book", "The Embedded Rust Book", "embedded-book/index.html"),
];

fn doc(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let toolchain = explicit_or_dir_toolchain(cfg, m)?;
    if let Ok(distributable) = DistributableToolchain::new(&toolchain) {
        let components = distributable.list_components()?;
        if let [_] = components
            .into_iter()
            .filter(|cstatus| {
                cstatus.component.short_name_in_manifest() == "rust-docs" && !cstatus.installed
            })
            .take(1)
            .collect::<Vec<ComponentStatus>>()
            .as_slice()
        {
            info!(
                "`rust-docs` not installed in toolchain `{}`",
                toolchain.name()
            );
            info!(
                "To install, try `rustup component add --toolchain {} rust-docs`",
                toolchain.name()
            );
            return Err(anyhow!(
                "unable to view documentation which is not installed"
            ));
        }
    }
    let topical_path: PathBuf;

    let doc_url = if let Some(topic) = m.value_of("topic") {
        topical_path = topical_doc::local_path(&toolchain.doc_path("").unwrap(), topic)?;
        topical_path.to_str().unwrap()
    } else if let Some((_, _, path)) = DOCS_DATA.iter().find(|(name, _, _)| m.is_present(name)) {
        path
    } else {
        "index.html"
    };

    if m.is_present("path") {
        let doc_path = toolchain.doc_path(doc_url)?;
        writeln!(process().stdout(), "{}", doc_path.display())?;
        Ok(utils::ExitCode(0))
    } else {
        toolchain.open_docs(doc_url)?;
        Ok(utils::ExitCode(0))
    }
}

fn man(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    let command = m.value_of("command").unwrap();

    let toolchain = explicit_or_dir_toolchain(cfg, m)?;
    let mut toolchain = toolchain.path().to_path_buf();
    toolchain.push("share");
    toolchain.push("man");
    utils::assert_is_directory(&toolchain)?;

    let mut manpaths = std::ffi::OsString::from(toolchain);
    manpaths.push(":"); // prepend to the default MANPATH list
    if let Some(path) = process().var_os("MANPATH") {
        manpaths.push(path);
    }
    Command::new("man")
        .env("MANPATH", manpaths)
        .arg(command)
        .status()
        .expect("failed to open man page");
    Ok(utils::ExitCode(0))
}

fn self_uninstall(m: &ArgMatches) -> Result<utils::ExitCode> {
    let no_prompt = m.is_present("no-prompt");

    self_update::uninstall(no_prompt)
}

fn set_default_host_triple(cfg: &Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    cfg.set_default_host_triple(m.value_of("host_triple").unwrap())?;
    Ok(utils::ExitCode(0))
}

fn set_profile(cfg: &mut Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    cfg.set_profile(m.value_of("profile-name").unwrap())?;
    Ok(utils::ExitCode(0))
}

fn set_auto_self_update(cfg: &mut Cfg, m: &ArgMatches) -> Result<utils::ExitCode> {
    if self_update::NEVER_SELF_UPDATE {
        let mut args = crate::process().args_os();
        let arg0 = args.next().map(PathBuf::from);
        let arg0 = arg0
            .as_ref()
            .and_then(|a| a.to_str())
            .ok_or(CLIError::NoExeName)?;
        warn!("{} is built with the no-self-update feature: setting auto-self-update will not have any effect.",arg0);
    }
    cfg.set_auto_self_update(m.value_of("auto-self-update-mode").unwrap())?;
    Ok(utils::ExitCode(0))
}

fn show_profile(cfg: &Cfg) -> Result<utils::ExitCode> {
    writeln!(process().stdout(), "{}", cfg.get_profile()?)?;
    Ok(utils::ExitCode(0))
}

fn show_keys(cfg: &Cfg) -> Result<utils::ExitCode> {
    for key in cfg.get_pgp_keys() {
        for l in key.show_key()? {
            info!("{}", l);
        }
    }
    Ok(utils::ExitCode(0))
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum CompletionCommand {
    Rustup,
    Cargo,
}

static COMPLETIONS: &[(&str, CompletionCommand)] = &[
    ("rustup", CompletionCommand::Rustup),
    ("cargo", CompletionCommand::Cargo),
];

impl CompletionCommand {
    fn variants() -> Vec<&'static str> {
        COMPLETIONS.iter().map(|&(s, _)| s).collect::<Vec<_>>()
    }
}

impl FromStr for CompletionCommand {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match COMPLETIONS
            .iter()
            .find(|&(val, _)| val.eq_ignore_ascii_case(s))
        {
            Some(&(_, cmd)) => Ok(cmd),
            None => {
                let completion_options = COMPLETIONS
                    .iter()
                    .map(|&(v, _)| v)
                    .fold("".to_owned(), |s, v| format!("{}{}, ", s, v));
                Err(format!(
                    "[valid values: {}]",
                    completion_options.trim_end_matches(", ")
                ))
            }
        }
    }
}

impl fmt::Display for CompletionCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match COMPLETIONS.iter().find(|&(_, cmd)| cmd == self) {
            Some(&(val, _)) => write!(f, "{}", val),
            None => unreachable!(),
        }
    }
}

fn output_completion_script(shell: Shell, command: CompletionCommand) -> Result<utils::ExitCode> {
    match command {
        CompletionCommand::Rustup => {
            cli().gen_completions_to("rustup", shell, &mut term2::stdout());
        }
        CompletionCommand::Cargo => {
            if let shells::Zsh = shell {
                writeln!(term2::stdout(), "#compdef cargo")?;
            }

            let script = match shell {
                shells::Bash => "/etc/bash_completion.d/cargo",
                shells::Zsh => "/share/zsh/site-functions/_cargo",
                _ => {
                    return Err(anyhow!(
                        "{} does not currently support completions for {}",
                        command,
                        shell
                    ))
                }
            };

            writeln!(
                term2::stdout(),
                "if command -v rustc >/dev/null 2>&1; then\n\
                    \tsource \"$(rustc --print sysroot)\"{}\n\
                 fi",
                script,
            )?;
        }
    }

    Ok(utils::ExitCode(0))
}
