-- ============================================================
-- NACSystem - Database Schema & Seed Data
-- ============================================================
-- This script runs ONCE on the very first PostgreSQL start
-- (when the pg_data volume is empty).
--
-- It creates the standard FreeRADIUS tables and inserts
-- test data so we can verify authentication works.
-- ============================================================


-- ────────────────────────────────────────────────────────────
-- TABLE: radcheck
-- ────────────────────────────────────────────────────────────
-- WHY: FreeRADIUS looks up this table during AUTHENTICATION.
--      Each row is a "check item" — a condition that must be
--      true for the user to be allowed in (e.g. password match).
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS radcheck (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(64) NOT NULL,       -- who is trying to authenticate
    attribute   VARCHAR(64) NOT NULL,       -- RADIUS attribute name (e.g. "Cleartext-Password")
    op          VARCHAR(2)  NOT NULL DEFAULT ':=',  -- operator (:= means "set this value")
    value       VARCHAR(253) NOT NULL       -- the value to check against
);
CREATE INDEX idx_radcheck_username ON radcheck(username);


-- ────────────────────────────────────────────────────────────
-- TABLE: radreply
-- ────────────────────────────────────────────────────────────
-- WHY: After authentication succeeds, FreeRADIUS reads this
--      table to find REPLY attributes to send back to the
--      network device (e.g. "put this user on VLAN 20").
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS radreply (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(64) NOT NULL,
    attribute   VARCHAR(64) NOT NULL,
    op          VARCHAR(2)  NOT NULL DEFAULT ':=',
    value       VARCHAR(253) NOT NULL
);
CREATE INDEX idx_radreply_username ON radreply(username);


-- ────────────────────────────────────────────────────────────
-- TABLE: radusergroup
-- ────────────────────────────────────────────────────────────
-- WHY: Maps a user to a group. This is how we say
--      "testuser belongs to the employee group".
--      FreeRADIUS checks group membership for authorization.
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS radusergroup (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(64) NOT NULL,
    groupname   VARCHAR(64) NOT NULL,
    priority    INTEGER     NOT NULL DEFAULT 1  -- lower number = higher priority
);
CREATE INDEX idx_radusergroup_username ON radusergroup(username);


-- ────────────────────────────────────────────────────────────
-- TABLE: radgroupreply
-- ────────────────────────────────────────────────────────────
-- WHY: Defines reply attributes for an entire GROUP.
--      Instead of setting VLAN per-user, we set it per-group.
--      Every user in "employee" group gets VLAN 20, etc.
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS radgroupreply (
    id          SERIAL PRIMARY KEY,
    groupname   VARCHAR(64) NOT NULL,
    attribute   VARCHAR(64) NOT NULL,
    op          VARCHAR(2)  NOT NULL DEFAULT ':=',
    value       VARCHAR(253) NOT NULL
);
CREATE INDEX idx_radgroupreply_groupname ON radgroupreply(groupname);


-- ────────────────────────────────────────────────────────────
-- TABLE: radacct  (ACCOUNTING)
-- ────────────────────────────────────────────────────────────
-- WHY: FreeRADIUS writes a row here every time a user starts
--      or stops a network session. This is the "Accounting"
--      part of AAA — it answers "who was connected, and when?"
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS radacct (
    radacctid           BIGSERIAL PRIMARY KEY,
    acctsessionid       VARCHAR(64) NOT NULL,       -- unique session ID from the NAS
    acctuniqueid        VARCHAR(32) NOT NULL UNIQUE, -- globally unique session ID
    username            VARCHAR(64),
    nasipaddress        VARCHAR(15),                -- IP of the switch/AP that sent the packet
    nasportid           VARCHAR(50),                -- physical port on the switch
    acctstarttime       TIMESTAMP,                  -- when the session started
    acctupdatetime      TIMESTAMP,                  -- last interim update
    acctstoptime        TIMESTAMP,                  -- when the session ended (NULL if still active)
    acctsessiontime     INTEGER,                    -- total session duration in seconds
    acctinputoctets     BIGINT DEFAULT 0,           -- bytes received by user
    acctoutputoctets    BIGINT DEFAULT 0,           -- bytes sent by user
    acctterminatecause  VARCHAR(32),                -- why the session ended (e.g. "User-Request")
    framedipaddress     VARCHAR(15),                -- IP assigned to the user
    callingStationid    VARCHAR(50)                 -- MAC address of the user's device
);
CREATE INDEX idx_radacct_username ON radacct(username);
CREATE INDEX idx_radacct_start ON radacct(acctstarttime);


-- ============================================================
-- SEED DATA
-- ============================================================


-- ── Group Definitions ───────────────────────────────────────
-- Each group gets a VLAN assignment via Tunnel-* attributes.
-- These are standard RADIUS attributes that tell the switch
-- which VLAN to place the authenticated user on.
--
-- Tunnel-Type = VLAN (13)        → we're assigning a VLAN
-- Tunnel-Medium-Type = IEEE-802 (6) → it's an Ethernet VLAN
-- Tunnel-Private-Group-Id = N    → the actual VLAN number

-- Admin group → VLAN 10 (management network)
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
    ('admin', 'Tunnel-Type',             ':=', '13'),
    ('admin', 'Tunnel-Medium-Type',      ':=', '6'),
    ('admin', 'Tunnel-Private-Group-Id', ':=', '10');

-- Employee group → VLAN 20 (corporate network)
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
    ('employee', 'Tunnel-Type',             ':=', '13'),
    ('employee', 'Tunnel-Medium-Type',      ':=', '6'),
    ('employee', 'Tunnel-Private-Group-Id', ':=', '20');

-- Guest group → VLAN 30 (restricted internet-only network)
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
    ('guest', 'Tunnel-Type',             ':=', '13'),
    ('guest', 'Tunnel-Medium-Type',      ':=', '6'),
    ('guest', 'Tunnel-Private-Group-Id', ':=', '30');


-- ── Test User: testuser ─────────────────────────────────────
-- Password is "testpass123", stored as a SHA-256 hash.
-- WHY SHA-256: MD4 (NT-Password) is deprecated and blocked in
-- Python 3.13 / OpenSSL 3.x. SHA-256 is secure and universal.
-- Since our FastAPI handles auth (not FreeRADIUS directly),
-- we can use any hash we want.
-- Generated with: echo -n "testpass123" | sha256sum
INSERT INTO radcheck (username, attribute, op, value) VALUES
    ('testuser', 'SHA-256-Password', ':=', '7e6e0c3079a08c5cc6036789b57e951f65f82383913ba1a49ae992544f1b4b6e');

-- Assign testuser to the employee group
INSERT INTO radusergroup (username, groupname, priority) VALUES
    ('testuser', 'employee', 1);


-- ── Dummy MAC Address for MAB Testing ───────────────────────
-- WHY: MAC Authentication Bypass (MAB) is used for devices that
--      can't do 802.1X (like printers, IP phones). The switch
--      sends the device's MAC address as the username AND password.
-- FreeRADIUS will look up the MAC in radcheck just like a regular user.
-- Format: lowercase, colon-separated (aa:bb:cc:dd:ee:ff)
INSERT INTO radcheck (username, attribute, op, value) VALUES
    ('00:11:22:33:44:55', 'Cleartext-Password', ':=', '00:11:22:33:44:55');

-- Assign the MAC device to the guest group (restricted VLAN)
INSERT INTO radusergroup (username, groupname, priority) VALUES
    ('00:11:22:33:44:55', 'guest', 1);
