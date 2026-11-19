"""Synthetic seed lines for parser fuzzing (shared by Hypothesis and Atheris).

All values are synthetic: ``*.demo`` hosts and users, RFC 5737 addresses.
"""

SSH_SEEDS = [
    "Jan  5 12:34:56 host1.demo sshd[1234]: Failed password for alice.demo from 192.0.2.10 port 50022 ssh2",
    "Jan  5 12:34:57 host1.demo sshd[1234]: Accepted publickey for bob.demo from 198.51.100.7 port 41000 ssh2",
    "Jan  5 12:34:58 host1.demo sshd[1234]: Failed password for invalid user root from 203.0.113.9 port 2222 ssh2",
    "Jan  5 12:35:00 host1.demo sshd[1234]: pam_unix(sshd:session): session opened for user alice.demo",
    "Jan  5 12:35:01 host1.demo sudo[999]: alice.demo : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/ls",
]

SYSLOG_SEEDS = [
    "Mar 10 08:00:01 host2.demo CRON[2001]: (root) CMD (run-parts /etc/cron.hourly)",
    "Mar 10 08:00:02 host2.demo systemd[1]: Started Daily apt download activities.",
    "Mar 10 08:00:03 host2.demo kernel: [12.3] eth0 up",
    "Mar 10 08:00:04 host2.demo kernel: insmod module loaded",
    "Mar 10 08:00:05 host2.demo su[3003]: FAILED SU (to root) for carol.demo on pts/1",
    "<34>1 2026-03-10T08:00:06Z host2.demo app 42 ID47 - message text",
]

WINDOWS_SEEDS = [
    "4625|2026-03-10T08:00:00Z|dave.demo|192.0.2.20|host3.demo|LogonType=3",
    "4624|2026-03-10T08:00:01Z|dave.demo|192.0.2.20|host3.demo",
    (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4625</EventID><TimeCreated SystemTime=\"2026-03-10T08:00:02Z\"/>"
        "<Computer>host3.demo</Computer></System><EventData>"
        '<Data Name="TargetUserName">dave.demo</Data><Data Name="IpAddress">192.0.2.20</Data>'
        '<Data Name="LogonType">3</Data></EventData></Event>'
    ),
    (
        "<Event><System><EventID>4672</EventID><Computer>host3.demo</Computer></System>"
        '<EventData><Data Name="SubjectUserName">erin.demo</Data></EventData></Event>'
    ),
]

NETWORK_SEEDS = [
    "2026-03-10T08:00:00Z,192.0.2.30,198.51.100.40,51515,443,tcp,1500,10",
    "2026-03-10T08:00:01Z 192.0.2.30:51516 -> 198.51.100.40:22 tcp 4096",
    "Mar 10 08:00:02 fw1.demo kernel: IN=eth0 OUT= SRC=203.0.113.5 DST=192.0.2.30 PROTO=TCP SPT=40000 DPT=3389",
]

ENDPOINT_SEEDS = [
    "2026-03-10T08:00:00Z|dev-1|frank.demo|powershell.exe|winword.exe|powershell -enc AAAA|C:\\Users\\frank\\a.ps1|process_create",
    "2026-03-10T08:00:01Z|dev-1|frank.demo|certutil.exe|cmd.exe|certutil -decode a b|C:\\temp\\b.exe|file_write",
    (
        '{"timestamp": "2026-03-10T08:00:02Z", "username": "frank.demo", '
        '"process_name": "rundll32.exe", "parent_process": "excel.exe", '
        '"cmdline": "rundll32 x.dll", "file_path": "/tmp/x.sh", "action": "dll_load"}'
    ),
]

ALL_SEEDS = SSH_SEEDS + SYSLOG_SEEDS + WINDOWS_SEEDS + NETWORK_SEEDS + ENDPOINT_SEEDS
