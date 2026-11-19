# Sigma rules

LSADRA's Sigma layer (`lsadra/detection/sigma_engine.py`) loads every `.yml` file in this
folder with [pySigma](https://github.com/SigmaHQ/pySigma) and runs it in-process against
each detection frame. See the "Sigma rules" part of the main README for how the layer is
switched on, and `docs/detection/scorecard.md` for how it does on the demo corpus.

| Folder | What it holds |
|---|---|
| `sigmahq/` | Rules copied unchanged from the SigmaHQ rule repository |
| `lsadra/` | Rules written for LSADRA, including the password-spraying correlation rule |
| `filters/` | Reviewed suppressions, in Sigma's filter format |

Rules are code: pySigma compiles each one to Python. Only add files you have reviewed.

## Adding a rule

1. Use the Sigma 2.0 format with a unique `id`, a `name` (needed if a correlation rule
   refers to it), `status`, `level`, and ATT&CK tags (`attack.t1053.003`). Tags must name
   a technique that is current in ATT&CK v20.1; `tests/test_sigma_engine.py` checks this.
2. Map only fields the layer fills in: `Image`, `OriginalFileName`, `CommandLine`,
   `ParentImage`, `ParentCommandLine`, `User`, `TargetFilename`, `TargetObject`, `Details`,
   `ServiceName`, `ImagePath`, `TaskName`, `TargetUserName`, `SourceIp`, `DestinationIp`,
   `DestinationPort`, `Outcome`, and for Windows log events `EventID` and `Provider_Name`.
3. Add a positive and a negative event to `tests/test_sigma_engine.py`, then run
   `python scripts/detection_scorecard.py` and commit the updated scorecard.

## Suppressing a false positive

Add a Sigma filter to `filters/suppressions.yml` (bundled) or to a file named by
`LSADRA_SIGMA_SUPPRESSIONS` (site-specific). A filter names the rules it applies to and a
`condition: not selection`; see the bundled example. Each suppression should say who
reviewed it and why in its `description`.

## Attribution and licence

The rules in `sigmahq/` come from the [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma)
(`master`, fetched 2026-11-18) and are licensed under the
[Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
They are unmodified: each file keeps its original `title`, `id`, `author`, `references`
and upstream file name, which is how DRL 1.1 asks for attribution. The rule authors are
credited in each file's `author` field. The DRL applies to those files only; the rest of
LSADRA is under the licence in the repository root.

pySigma is a dependency under the GNU LGPL 2.1, used unmodified as a library.

### Rules taken from SigmaHQ

- `file_event_lnx_doas_conf_creation.yml`: Linux Doas Conf File Creation (Sittikorn S, Teoderick Contreras)
- `file_event_lnx_persistence_sudoers_files.yml`: Persistence Via Sudoers Files (Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_lnx_base64_execution.yml`: Linux Base64 Encoded Pipe to Shell (pH-T (Nextron Systems))
- `proc_creation_lnx_base64_shebang_cli.yml`: Linux Base64 Encoded Shebang In CLI (Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_lnx_chattr_immutable_removal.yml`: Remove Immutable File Attribute (Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_lnx_clear_logs.yml`: Linux Logs Clearing Attempts (Ömer Günal, oscd.community)
- `proc_creation_lnx_clear_syslog.yml`: Syslog Clearing or Removal Via System Utilities (Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC)
- `proc_creation_lnx_crontab_removal.yml`: Remove Scheduled Cron Task/Job (Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_lnx_crypto_mining.yml`: Linux Crypto Mining Indicators (Florian Roth (Nextron Systems))
- `proc_creation_lnx_curl_wget_exec_tmp.yml`: Suspicious Download and Execute Pattern via Curl/Wget (Aayush Gupta)
- `proc_creation_lnx_disable_ufw.yml`: UFW Disable Attempt (Joseliyo Sanchez, @Joseliyo_Jstnk)
- `proc_creation_lnx_iptables_flush_ufw.yml`: Flush Iptables Ufw Chain (Joseliyo Sanchez, @Joseliyo_Jstnk)
- `proc_creation_lnx_netcat_reverse_shell.yml`: Potential Netcat Reverse Shell Execution ('@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)')
- `proc_creation_lnx_nohup.yml`: Nohup Execution ('Christopher Peacock @SecurePeacock, SCYTHE @scythe_io')
- `proc_creation_lnx_perl_reverse_shell.yml`: Potential Perl Reverse Shell Execution ('@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)')
- `proc_creation_lnx_php_reverse_shell.yml`: Potential PHP Reverse Shell ('@d4ns4n_')
- `proc_creation_lnx_python_reverse_shell.yml`: Python Reverse Shell Execution Via PTY And Socket Modules ('@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)')
- `proc_creation_lnx_ruby_reverse_shell.yml`: Potential Ruby Reverse Shell ('@d4ns4n_')
- `proc_creation_lnx_schedule_task_job_cron.yml`: Scheduled Cron Task/Job - Linux (Alejandro Ortuno, oscd.community)
- `proc_creation_lnx_security_tools_disabling.yml`: Disabling Security Tools (Ömer Günal, Alejandro Ortuno, oscd.community)
- `proc_creation_lnx_ssh_shell_execution.yml`: Shell Invocation Via Ssh - Linux (Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.))
- `proc_creation_lnx_susp_curl_useragent.yml`: Suspicious Curl Change User Agents - Linux (Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_lnx_susp_history_delete.yml`: History File Deletion (Florian Roth (Nextron Systems))
- `proc_creation_lnx_susp_interactive_bash.yml`: Interactive Bash Suspicious Children (Florian Roth (Nextron Systems))
- `proc_creation_lnx_susp_java_children.yml`: Suspicious Java Children Processes (Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_lnx_systemctl_mask_power_settings.yml`: Mask System Power Settings Via Systemctl (Milad Cheraghi, Nasreddine Bencherchali)
- `proc_creation_lnx_touch_susp.yml`: Touch Suspicious Service File (Joseliyo Sanchez, @Joseliyo_Jstnk)
- `proc_creation_lnx_userdel.yml`: User Has Been Deleted Via Userdel (Tuan Le (NCSGroup))
- `proc_creation_lnx_wget_download_suspicious_directory.yml`: Download File To Potentially Suspicious Directory Via Wget (Joseliyo Sanchez, @Joseliyo_Jstnk)
- `proc_creation_win_bcdedit_boot_conf_tamper.yml`: Boot Configuration Tampering Via Bcdedit.EXE (E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community)
- `proc_creation_win_bitsadmin_download.yml`: File Download Via Bitsadmin (Michael Haag, FPT.EagleEye)
- `proc_creation_win_certutil_decode.yml`: File Decoded From Base64/Hex Via Certutil.EXE (Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community)
- `proc_creation_win_certutil_download.yml`: Suspicious Download Via Certutil.EXE (Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_win_certutil_encode.yml`: File Encoded To Base64 Via Certutil.EXE (Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_win_hktl_mimikatz_command_line.yml`: HackTool - Mimikatz Execution (Teymur Kheirkhabarov, oscd.community, David ANDRE (additional keywords), Tim Shelton)
- `proc_creation_win_mshta_http.yml`: Remotely Hosted HTA File Executed Via Mshta.EXE (Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_win_mshta_javascript.yml`: Suspicious JavaScript Execution Via Mshta.EXE (E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community)
- `proc_creation_win_mshta_susp_pattern.yml`: Suspicious Mshta.EXE Execution Patterns (Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_win_net_user_add.yml`: New User Created Via Net.EXE (Endgame, JHasenbusch (adapted to Sigma for oscd.community))
- `proc_creation_win_net_user_add_never_expire.yml`: New User Created Via Net.EXE With Never Expire Option (Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_win_office_susp_child_processes.yml`: Suspicious Microsoft Office Child Process (Florian Roth (Nextron Systems), Markus Neis, FPT.EagleEye Team, Vadim Khrykov, Cyb3rEng, Michael Haag, Christopher Peacock @securepeacock, @scythe_io)
- `proc_creation_win_powershell_base64_encoded_cmd.yml`: Suspicious Encoded PowerShell Command Line (Florian Roth (Nextron Systems), Markus Neis, Jonhnathan Ribeiro, Daniil Yugoslavskiy, Anton Kutepov, oscd.community)
- `proc_creation_win_powershell_download_iex.yml`: PowerShell Download and Execution Cradles (Florian Roth (Nextron Systems))
- `proc_creation_win_powershell_susp_download_patterns.yml`: Suspicious PowerShell Download and Execute Pattern (Florian Roth (Nextron Systems))
- `proc_creation_win_reg_add_run_key.yml`: Potential Persistence Attempt Via Run Keys Using Reg.EXE (Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems))
- `proc_creation_win_regsvr32_susp_parent.yml`: Scripting/CommandLine Process Spawned Regsvr32 (Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_win_rundll32_susp_activity.yml`: Potentially Suspicious Rundll32 Activity (juju4, Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems))
- `proc_creation_win_schtasks_susp_pattern.yml`: Suspicious Command Patterns In Scheduled Task Creation (Florian Roth (Nextron Systems))
- `proc_creation_win_susp_execution_path.yml`: Process Execution From A Potentially Suspicious Folder (Florian Roth (Nextron Systems), Tim Shelton)
- `proc_creation_win_susp_shadow_copies_deletion.yml`: Shadow Copies Deletion Using Operating Systems Utilities (Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades))
- `registry_set_asep_reg_keys_modification_currentversion.yml`: CurrentVersion Autorun Keys Modification (Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split))
- `win_security_audit_log_cleared.yml`: Security Eventlog Cleared (Florian Roth (Nextron Systems))
- `win_security_susp_local_anon_logon_created.yml`: Suspicious Windows ANONYMOUS LOGON Local Account Created (James Pemberton / @4A616D6573)
- `win_security_user_added_to_local_administrators.yml`: User Added to Local Administrator Group (Florian Roth (Nextron Systems))
- `win_system_service_install_susp.yml`: Suspicious Service Installation (pH-T (Nextron Systems), Florian Roth (Nextron Systems))
- `win_system_susp_service_installation_folder.yml`: Service Installation in Suspicious Folder (pH-T (Nextron Systems))
