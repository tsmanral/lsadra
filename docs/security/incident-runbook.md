# Operator incident runbook

What to do when something goes wrong with **your own LSADRA deployment**. For
vulnerabilities in LSADRA itself, report privately as described in
[SECURITY.md](https://github.com/tsmanral/lsadra/blob/main/SECURITY.md) instead.

Each playbook follows the same order: **contain, rotate, check, recover**. Keep
a short written log as you go (time, what you saw, what you changed). It is the
first thing you will want afterwards.

**Preserve evidence first.** Deleting a device in LSADRA also deletes its
events, alerts and incidents. Before you delete anything, copy the database
(`data/sentinel_v3.db`): stop the server and copy the file, or run
`sqlite3 data/sentinel_v3.db ".backup evidence-$(date +%F).db"` while it runs.
Keep that copy somewhere only you can read.

## 1. The server signing secret leaked

`LSADRA_JWT_SECRET` signs every dashboard session. Anyone holding it can mint a
session for any user and role.

1. **Contain.** Stop the server, or block its port at the firewall, so no forged
   session can be used while you work.
2. **Rotate.** Generate a new secret (for example
   `python -c "import secrets; print(secrets.token_urlsafe(48))"`), put it in
   the environment or `.env`, and restart. Every existing session becomes
   invalid at once, so everyone signs in again.
3. **Check.** Review users and roles in **Admin**: remove accounts you do not
   recognise and reset passwords for the rest. Look at device registrations made
   since the suspected leak.
4. **Recover.** Find how it leaked (a committed `.env`, a shared screenshot, a
   backup, a container image layer) and close that path. If it reached a git
   repository, rotating is the fix; rewriting history does not un-leak it.

## 2. A device API key leaked

A device key lets its holder write events as that device, which can hide real
activity behind fake noise.

1. **Contain.** Preserve evidence (see above), then delete the device in
   **Sources** (`DELETE /api/dashboard/devices/{device_id}`). The key stops
   working on its next request.
2. **Rotate.** Generate a new registration token and re-enrol the real host. It
   receives a new device ID and key.
3. **Check.** In your evidence copy, review the device's events from the
   suspected leak onward. Events sent while the key was in other hands cannot
   be trusted.
4. **Recover.** Store the new key readable only by the agent's service user.

## 3. A monitored host is compromised

LSADRA treats agent hosts as untrusted, so a compromised host should not reach
the server. It can still lie about itself.

1. **Contain.** Isolate the host by your normal means (pull the network cable,
   quarantine VLAN, cloud security group). LSADRA's response playbooks are dry
   runs unless you have approved live actions.
2. **Preserve.** Copy the database (see above) before retention removes the
   host's history. Raw events expire after `LSADRA_RETENTION_DAYS` (default 30);
   alerts last `LSADRA_ALERT_RETENTION_DAYS` (default 365).
3. **Rotate.** Delete the device in LSADRA (playbook 2). Assume every secret on
   that host is known to the attacker, including the agent key.
4. **Recover.** Rebuild the host from known-good media, re-enrol it with a new
   key, and watch it closely for a week.

## 4. The LSADRA server itself is compromised

Treat everything the server held as disclosed: signing secret, device key
hashes, user password hashes, and all logged data.

1. **Contain.** Take the server off the network. Keep the disk for analysis.
2. **Rebuild.** Install on a clean host from a release you verify. Do not reuse
   the old `.env` or model files.
3. **Rotate everything.** New signing secret (playbook 1), new device keys for
   every host (playbook 2), and new passwords for every dashboard user.
4. **Notify.** Raw events can include personal data about the people using the
   monitored hosts. Check whether your local law requires you to tell anyone.

## 5. A dashboard account is compromised

1. **Contain.** In **Admin**, set a new password for the account and lower it
   to the lowest role. Rotate the signing secret (playbook 1) to end its current
   session at once.
2. **Check.** Review what the account could reach: incidents it changed, devices
   it registered or deleted, exports it ran.
3. **Recover.** Restore the account with a new password, and enable stronger
   sign-in when it is available.

## 6. The database file was copied

1. **Contain.** Find how (backup share, stolen laptop, misconfigured volume) and
   close it.
2. **Rotate.** Device keys are stored as bcrypt hashes, but rotate dashboard
   passwords and device keys anyway. The signing secret is not stored in the
   database.
3. **Notify.** As in playbook 4, the raw events may be personal data.
4. **Prevent.** Keep the data directory readable only by the service user and
   run the server on a disk with full-disk encryption.

## After any incident

- Write down what happened, when you noticed, and what you changed.
- If LSADRA missed something it should have caught, or made the incident
  harder, open an issue (or a private advisory if it is a vulnerability).
