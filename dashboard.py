import csv
from datetime import datetime, timedelta
from pathlib import Path
from html import escape

import pandas as pd
import streamlit as st


# ============================================================
# IdentityShield AI — educational SOC dashboard
# Rule-based detection using local or simulated login data.
# ============================================================

st.set_page_config(
    page_title="IdentityShield AI | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "data" / "login_logs.csv"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
REQUIRED_COLUMNS = {"timestamp", "username", "event_type", "source_ip"}

st.markdown(
    """
    <style>
    .stApp { background: #0b1120; color: #e5eaf5; }
    [data-testid="stSidebar"] { background: #101a2d; }
    .block-container { max-width: 1500px; padding-top: 1.6rem; }
    h1,h2,h3 { color: #f1f5ff !important; }
    .brand { color:#60a5fa; font-size:12px; font-weight:800; letter-spacing:2px; }
    .subtle { color:#94a3b8; }
    .alert-card { background:#121e31; border:1px solid #293852;
        border-left:4px solid #fbbf24; border-radius:10px;
        padding:14px; margin-bottom:10px; }
    .alert-high { border-left-color:#f87171; }
    .alert-medium { border-left-color:#fbbf24; }
    [data-testid="stMetric"] { background:#121e31; border:1px solid #293852;
        padding:12px; border-radius:12px; }
    </style>
    """,
    unsafe_allow_html=True,
)


def sample_logs():
    """Training data used if the CSV file is missing."""
    now = datetime.now().replace(microsecond=0)
    rows = [
        (now - timedelta(minutes=32), "alex", "FAILED_LOGIN", "203.0.113.10"),
        (now - timedelta(minutes=31), "alex", "FAILED_LOGIN", "203.0.113.10"),
        (now - timedelta(minutes=30), "alex", "FAILED_LOGIN", "203.0.113.10"),
        (now - timedelta(minutes=29), "alex", "SUCCESS_LOGIN", "203.0.113.10"),
        (now - timedelta(minutes=24), "mira", "SUCCESS_LOGIN", "192.0.2.20"),
        (now - timedelta(minutes=18), "mira", "SUCCESS_LOGIN", "192.0.2.21"),
        (now - timedelta(minutes=12), "sam", "FAILED_LOGIN", "198.51.100.7"),
        (now - timedelta(minutes=11), "sam", "FAILED_LOGIN", "198.51.100.7"),
        (now - timedelta(minutes=10), "sam", "SUCCESS_LOGIN", "198.51.100.7"),
        (now - timedelta(minutes=5), "lee", "SUCCESS_LOGIN", "192.0.2.55"),
    ]
    return [
        {"timestamp": t, "username": u, "event_type": e, "source_ip": ip}
        for t, u, e, ip in rows
    ]


@st.cache_data
def load_logs(file_path, modified_time):
    """Load and validate the local login-events CSV."""
    del modified_time
    records = []

    with open(file_path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        if (
            not reader.fieldnames
            or not REQUIRED_COLUMNS.issubset(reader.fieldnames)
        ):
            raise ValueError(
                "CSV must contain these columns: timestamp, username, "
                "event_type, source_ip"
            )

        for row in reader:
            try:
                timestamp = datetime.strptime(
                    row["timestamp"].strip(), TIME_FORMAT
                )
                username = row["username"].strip()
                event_type = row["event_type"].strip().upper()
                source_ip = row["source_ip"].strip()

                if not username or not source_ip:
                    continue

                if event_type not in {"FAILED_LOGIN", "SUCCESS_LOGIN"}:
                    continue

                records.append({
                    "timestamp": timestamp,
                    "username": username,
                    "event_type": event_type,
                    "source_ip": source_ip,
                })

            except (ValueError, AttributeError, TypeError):
                continue

    return sorted(records, key=lambda event: event["timestamp"])


def mitre_mapping(rule):
    """Return a cautious, rule-specific MITRE ATT&CK mapping."""
    if rule in {"Repeated failed logins", "Failures followed by success"}:
        return {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "technique_url": "https://attack.mitre.org/techniques/T1110/",
            "mapping_note": (
                "Potentially relevant to credential guessing; validate with "
                "additional evidence. This is not proof of an attack."
            ),
        }

    return {
        "technique_id": "UNMAPPED",
        "technique_name": "No direct technique mapping",
        "technique_url": "https://attack.mitre.org/",
        "mapping_note": (
            "This signal alone does not establish a specific technique."
        ),
    }


def investigate(records):
    """Generate rule-based alerts and illustrative account risk scores."""
    alerts = []
    accounts = sorted({event["username"] for event in records})

    signals = {
        username: {
            "multiple_ips": False,
            "repeated_failures": False,
            "failure_then_success": False,
        }
        for username in accounts
    }

    for username in accounts:
        user_events = [
            event for event in records
            if event["username"] == username
        ]
        ips = sorted({event["source_ip"] for event in user_events})

        # Rule 1: The same account appears from multiple IP addresses.
        if len(ips) > 1:
            signals[username]["multiple_ips"] = True

            alert = {
                "severity": "MEDIUM",
                "rule": "Multiple source IPs",
                "username": username,
                "source_ip": ", ".join(ips),
                "timestamp": "",
                "details": (
                    f"Account appeared from {len(ips)} different "
                    "source IP addresses."
                ),
                "recommendation": (
                    "Verify whether these addresses and access patterns "
                    "are expected."
                ),
            }
            alert.update(mitre_mapping(alert["rule"]))
            alerts.append(alert)

        # Group the account's events by source IP.
        by_ip = {}
        for event in user_events:
            by_ip.setdefault(event["source_ip"], []).append(event)

        for ip, events in by_ip.items():
            events.sort(key=lambda event: event["timestamp"])

            failures = [
                event["timestamp"] for event in events
                if event["event_type"] == "FAILED_LOGIN"
            ]
            successes = [
                event["timestamp"] for event in events
                if event["event_type"] == "SUCCESS_LOGIN"
            ]

            # Rule 2: Three or more failures followed by a success
            # within five minutes.
            failure_then_success = False

            for success_time in successes:
                recent_failures = [
                    failure_time for failure_time in failures
                    if (
                        success_time - timedelta(minutes=5)
                        <= failure_time < success_time
                    )
                ]

                if len(recent_failures) >= 3:
                    failure_then_success = True
                    signals[username]["failure_then_success"] = True

                    alert = {
                        "severity": "HIGH",
                        "rule": "Failures followed by success",
                        "username": username,
                        "source_ip": ip,
                        "timestamp": success_time.strftime(TIME_FORMAT),
                        "details": (
                            "At least three failed logins occurred in the "
                            "five minutes before a successful login."
                        ),
                        "recommendation": (
                            "Verify the successful login, review nearby "
                            "events, and escalate if unauthorized."
                        ),
                    }
                    alert.update(mitre_mapping(alert["rule"]))
                    alerts.append(alert)
                    break

            # Rule 3: Three or more failures in any five-minute window.
            for start_index, start_time in enumerate(failures):
                end_time = start_time + timedelta(minutes=5)

                count = sum(
                    1
                    for failure_time in failures[start_index:]
                    if start_time <= failure_time <= end_time
                )

                if count >= 3:
                    signals[username]["repeated_failures"] = True

                    # Avoid a duplicate alert for the same failure
                    # sequence already reported by Rule 2.
                    if not failure_then_success:
                        alert = {
                            "severity": "HIGH",
                            "rule": "Repeated failed logins",
                            "username": username,
                            "source_ip": ip,
                            "timestamp": start_time.strftime(TIME_FORMAT),
                            "details": (
                                f"{count} or more failed logins occurred "
                                "within a five-minute window."
                            ),
                            "recommendation": (
                                "Review the login timeline and verify "
                                "the activity with the account owner."
                            ),
                        }
                        alert.update(mitre_mapping(alert["rule"]))
                        alerts.append(alert)

                    break

    # Illustrative risk scoring; these are not validated industry scores.
    account_signals = {}

    for username, flags in signals.items():
        score = 0
        reasons = []

        if flags["multiple_ips"]:
            score += 20
            reasons.append("Multiple source IPs (+20)")

        if flags["repeated_failures"]:
            score += 30
            reasons.append("Repeated failed logins (+30)")

        if flags["failure_then_success"]:
            score += 40
            reasons.append("Success after repeated failures (+40)")

        score = min(score, 100)
        level = (
            "HIGH" if score >= 60
            else "MEDIUM" if score >= 30
            else "LOW"
        )

        account_signals[username] = {
            "risk_score": score,
            "risk_level": level,
            "risk_reasons": reasons or [
                "No configured risk signals detected"
            ],
        }

    alerts.sort(
        key=lambda alert: (
            alert["severity"] != "HIGH",
            alert["username"],
            alert["rule"],
        )
    )

    return alerts, account_signals


def make_incident_report(username, user_logs, user_alerts, signals):
    """Create a plain-text incident report for download."""
    failed = sum(
        event["event_type"] == "FAILED_LOGIN" for event in user_logs
    )
    success = sum(
        event["event_type"] == "SUCCESS_LOGIN" for event in user_logs
    )
    ips = sorted({event["source_ip"] for event in user_logs})

    priority = (
        "HIGH"
        if any(alert["severity"] == "HIGH" for alert in user_alerts)
        else "MEDIUM" if user_alerts else "LOW"
    )

    lines = [
        "IDENTITYSHIELD AI - INCIDENT INVESTIGATION REPORT",
        "=" * 56,
        f"Generated: {datetime.now().strftime(TIME_FORMAT)}",
        "Project: Educational SOC investigation prototype",
        "Data source: Local CSV or built-in simulated sample data",
        "",
        f"Account: {username}",
        f"Priority: {priority}",
        f"Risk score: {signals['risk_score']}/100 ({signals['risk_level']})",
        f"Total events: {len(user_logs)}",
        f"Failed logins: {failed}",
        f"Successful logins: {success}",
        "",
        "SOURCE IP ADDRESSES",
        *([f"- {ip}" for ip in ips] or ["- No IP addresses recorded"]),
        "",
        "RISK SIGNALS",
        *[f"- {reason}" for reason in signals["risk_reasons"]],
        "",
        "DETECTION FINDINGS",
    ]

    if user_alerts:
        for index, alert in enumerate(user_alerts, start=1):
            lines.extend([
                f"{index}. {alert['severity']} — {alert['rule']}",
                f"   Time: {alert['timestamp'] or 'Not specified'}",
                f"   Source IP: {alert['source_ip']}",
                f"   Details: {alert['details']}",
                (
                    f"   ATT&CK: {alert['technique_id']} — "
                    f"{alert['technique_name']}"
                ),
                f"   Mapping note: {alert['mapping_note']}",
                f"   Recommended action: {alert['recommendation']}",
                "",
            ])
    else:
        lines.append("- No configured detection rules triggered.")

    lines.extend([
        "",
        "LIMITATIONS",
        "- Rule-based educational prototype; not an AI model.",
        "- Risk scores are illustrative, not validated industry scores.",
        "- Login signals are not proof of compromise.",
        "- No live SIEM or external threat intelligence is connected.",
        "- No containment actions are performed by this application.",
    ])

    return "\n".join(lines)


# ============================================================
# LOAD DATA — LIVE KALI EVENTS, CSV, OR SAMPLE DATA
# ============================================================

import json

LIVE_FILE = BASE_DIR / "data" / "live_login_events.jsonl"


def load_live_events(file_path):
    """Read JSON Lines written by live_receiver.py without caching."""
    records = []
    if not file_path.exists():
        return records

    with file_path.open("r", encoding="utf-8") as live_file:
        for line_number, line in enumerate(live_file, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                raw_timestamp = str(event.get("timestamp", "")).strip()
                try:
                    timestamp = datetime.strptime(raw_timestamp, TIME_FORMAT)
                except ValueError:
                    timestamp = datetime.fromisoformat(raw_timestamp)
                    if timestamp.tzinfo is not None:
                        timestamp = timestamp.replace(tzinfo=None)

                username = str(event.get("username", "")).strip()
                event_type = str(event.get("event_type", "")).strip().upper()
                source_ip = str(event.get("source_ip", "")).strip()

                if not username or not source_ip:
                    continue
                if event_type not in {"FAILED_LOGIN", "SUCCESS_LOGIN"}:
                    continue

                records.append({
                    "timestamp": timestamp,
                    "username": username,
                    "event_type": event_type,
                    "source_ip": source_ip,
                })
            except (json.JSONDecodeError, ValueError, TypeError, AttributeError):
                # Ignore incomplete or malformed lines, but keep reading later events.
                continue

    return sorted(records, key=lambda event: event["timestamp"])


# Load each available source independently so a single live test event does
# not hide the existing CSV training dataset.
live_logs = load_live_events(LIVE_FILE)
csv_logs = []

if LOG_FILE.exists():
    try:
        csv_logs = load_logs(str(LOG_FILE), LOG_FILE.stat().st_mtime)
    except Exception as exc:
        st.warning(f"Could not read {LOG_FILE}: {exc}")

if live_logs and csv_logs:
    logs = sorted(csv_logs + live_logs, key=lambda event: event["timestamp"])
    data_source = (
        f"Combined data: {len(csv_logs)} CSV event(s) + "
        f"{len(live_logs)} live receiver event(s)"
    )
elif live_logs:
    logs = live_logs
    data_source = f"Live receiver events ({len(live_logs)} valid event(s))"
elif csv_logs:
    logs = csv_logs
    data_source = f"Local CSV: {LOG_FILE.relative_to(BASE_DIR)}"
else:
    logs = sample_logs()
    data_source = "Built-in simulated sample data (no valid CSV/live events found)"

alerts, account_signals = investigate(logs)
accounts = sorted({event["username"] for event in logs})

alerts_by_user = {
    username: [alert for alert in alerts if alert["username"] == username]
    for username in accounts
}

st.markdown(
    '<div class="brand">IDENTITYSHIELD AI · SOC LAB</div>',
    unsafe_allow_html=True,
)
st.title("IdentityShield AI")
st.caption(
    "Rule-based authentication monitoring and investigation dashboard"
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.markdown("## 🛡️ IdentityShield")
    st.caption("Educational SOC Analyst lab")

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Security Alerts",
            "Risk Scores",
            "Login Events",
            "Investigate Account",
            "Incident Reports",
            "MITRE ATT&CK",
            "Investigation Assistant",
        ],
    )

    st.divider()
    st.caption("Data source")
    st.write(data_source)
    if st.button("Refresh live events", use_container_width=True):
        st.rerun()
    st.caption("Live file is reread on each dashboard run. Use Refresh live events to fetch newly received events.")


# ============================================================
# OVERVIEW
# ============================================================

if page == "Overview":
    st.subheader("Security Operations Center")
    st.caption("A quick view of authentication activity and rule-based detections.")

    high_risk_count = sum(
        signals["risk_level"] == "HIGH"
        for signals in account_signals.values()
    )
    high_alert_count = sum(alert["severity"] == "HIGH" for alert in alerts)
    medium_alert_count = sum(alert["severity"] == "MEDIUM" for alert in alerts)

    # Professional overview cards. Values are calculated from the loaded data.
    st.markdown(
        """
        <style>
        .soc-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin:8px 0 22px; }
        .soc-card { background:linear-gradient(145deg,#16243a,#111b2c); border:1px solid #2b3b55; border-radius:15px; padding:18px 18px 16px; min-height:124px; box-shadow:0 5px 16px rgba(0,0,0,.12); }
        .soc-label { color:#aab9ce; font-size:12px; font-weight:700; letter-spacing:.8px; text-transform:uppercase; margin-bottom:12px; }
        .soc-value { color:#f4f7ff; font-size:31px; line-height:1.1; font-weight:800; margin-bottom:8px; }
        .soc-note { color:#9aabc2; font-size:12px; }
        .soc-green { border-top:3px solid #34d399; }
        .soc-blue { border-top:3px solid #60a5fa; }
        .soc-amber { border-top:3px solid #fbbf24; }
        .soc-red { border-top:3px solid #f87171; }
        .soc-panel { background:#111c2e; border:1px solid #2b3b55; border-radius:14px; padding:16px 18px; margin:8px 0 18px; }
        .soc-panel-title { color:#edf3ff; font-size:16px; font-weight:750; margin-bottom:12px; }
        .soc-alert-row { display:flex; align-items:flex-start; gap:10px; padding:10px 0; border-bottom:1px solid #26364d; }
        .soc-alert-row:last-child { border-bottom:none; padding-bottom:0; }
        .soc-dot { width:9px; height:9px; border-radius:50%; margin-top:6px; flex:0 0 9px; }
        .soc-alert-title { color:#eef4ff; font-weight:700; font-size:13px; }
        .soc-alert-detail { color:#9aabc2; font-size:12px; margin-top:3px; }
        @media(max-width:900px) { .soc-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } }
        @media(max-width:520px) { .soc-grid { grid-template-columns:1fr 1fr; gap:8px; } .soc-card { padding:12px; min-height:108px; } .soc-value { font-size:25px; } }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <div class="soc-grid">
          <div class="soc-card soc-blue">
            <div class="soc-label">Accounts monitored</div>
            <div class="soc-value">{len(accounts)}</div>
            <div class="soc-note">Unique accounts in loaded events</div>
          </div>
          <div class="soc-card soc-green">
            <div class="soc-label">Login events</div>
            <div class="soc-value">{len(logs)}</div>
            <div class="soc-note">Valid authentication records</div>
          </div>
          <div class="soc-card soc-amber">
            <div class="soc-label">Security alerts</div>
            <div class="soc-value">{len(alerts)}</div>
            <div class="soc-note">{high_alert_count} high · {medium_alert_count} medium</div>
          </div>
          <div class="soc-card soc-red">
            <div class="soc-label">High-risk accounts</div>
            <div class="soc-value">{high_risk_count}</div>
            <div class="soc-note">Risk score at or above 60</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Compact alert snapshot uses the existing detection results; it does not
    # introduce new rules or alter scoring. Risk distribution stays off Overview.
    st.markdown('<div class="soc-panel"><div class="soc-panel-title">Recent detection activity</div>', unsafe_allow_html=True)
    if alerts:
        for alert in alerts[:4]:
            dot_color = "#f87171" if alert["severity"] == "HIGH" else "#fbbf24"
            st.markdown(
                f'<div class="soc-alert-row">'
                f'<span class="soc-dot" style="background:{dot_color};"></span>'
                f'<div><div class="soc-alert-title">{escape(alert["severity"])} · {escape(alert["rule"])} — {escape(alert["username"])}</div>'
                f'<div class="soc-alert-detail">{escape(alert["details"])}</div></div></div>',
                unsafe_allow_html=True,
            )
    else:
        st.markdown('<div class="soc-alert-detail">No configured detection rules have triggered.</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # Recent activity uses the full page width. Risk distribution remains on
    # the dedicated Risk Scores page, as requested.
    st.markdown("### Recent login activity")
    if logs:
        recent_df = pd.DataFrame(logs).sort_values(
            "timestamp", ascending=False
        ).head(10)
        recent_df["timestamp"] = recent_df["timestamp"].dt.strftime(TIME_FORMAT)
        st.dataframe(recent_df, use_container_width=True, hide_index=True)
    else:
        st.info("No login events available.")

    st.info("A rule match is a signal to investigate, not proof of malicious activity.")


# ============================================================
# SECURITY ALERTS
# ============================================================

elif page == "Security Alerts":
    st.subheader("Security alerts")

    severity_filter = st.multiselect(
        "Severity",
        ["HIGH", "MEDIUM"],
        default=["HIGH", "MEDIUM"],
    )
    account_filter = st.multiselect(
        "Account",
        accounts,
        default=accounts,
    )

    filtered = [
        alert for alert in alerts
        if (
            alert["severity"] in severity_filter
            and alert["username"] in account_filter
        )
    ]

    st.caption(f"{len(filtered)} matching alert(s)")

    if filtered:
        for alert in filtered:
            style = (
                "alert-high"
                if alert["severity"] == "HIGH"
                else "alert-medium"
            )

            st.markdown(
                f'<div class="alert-card {style}">'
                f'<b>{escape(alert["severity"])} · '
                f'{escape(alert["rule"])}</b><br>'
                f'Account: {escape(alert["username"])}<br>'
                f'Time: {escape(alert["timestamp"] or "Not specified")}<br>'
                f'Source IP: {escape(alert["source_ip"])}<br>'
                f'{escape(alert["details"])}<br>'
                f'ATT&CK: {escape(alert["technique_id"])} — '
                f'{escape(alert["technique_name"])}<br>'
                f'Recommendation: {escape(alert["recommendation"])}'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        st.success("No alerts match the selected filters.")


# ============================================================
# RISK SCORES
# ============================================================

elif page == "Risk Scores":
    st.subheader("Account risk scores")

    rows = [
        {
            "Account": username,
            "Risk score": signals["risk_score"],
            "Risk level": signals["risk_level"],
            "Risk signals": "; ".join(signals["risk_reasons"]),
        }
        for username, signals in account_signals.items()
    ]

    risk_df = pd.DataFrame(rows)

    if not risk_df.empty:
        risk_df = risk_df.sort_values(
            "Risk score", ascending=False
        )

        st.dataframe(
            risk_df,
            use_container_width=True,
            hide_index=True,
        )

        selected = st.selectbox(
            "View risk details for account",
            accounts,
        )
        signals = account_signals[selected]

        st.metric(
            "Risk score",
            f"{signals['risk_score']}/100",
            signals["risk_level"],
        )
        st.progress(signals["risk_score"] / 100)

        for reason in signals["risk_reasons"]:
            st.write(f"- {reason}")
    else:
        st.info("No accounts to score.")


# ============================================================
# LOGIN EVENTS
# ============================================================

elif page == "Login Events":
    st.subheader("Authentication event log")

    if logs:
        events_df = pd.DataFrame(logs)

        event_filter = st.multiselect(
            "Event type",
            ["FAILED_LOGIN", "SUCCESS_LOGIN"],
            default=["FAILED_LOGIN", "SUCCESS_LOGIN"],
        )
        account_filter = st.multiselect(
            "Accounts",
            accounts,
            default=accounts,
        )

        filtered_df = events_df[
            events_df["event_type"].isin(event_filter)
            & events_df["username"].isin(account_filter)
        ].sort_values("timestamp", ascending=False).copy()

        filtered_df["timestamp"] = filtered_df["timestamp"].dt.strftime(
            TIME_FORMAT
        )

        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True,
        )
        st.caption(f"Matching events: {len(filtered_df)}")
    else:
        st.info("No valid login events were found.")


# ============================================================
# INVESTIGATE ACCOUNT
# ============================================================

elif page == "Investigate Account":
    st.subheader("Account investigation")

    if not accounts:
        st.info("No accounts available.")
    else:
        username = st.selectbox("Select account", accounts)

        user_logs = [
            event for event in logs
            if event["username"] == username
        ]
        user_alerts = alerts_by_user.get(username, [])
        signals = account_signals[username]

        c1, c2, c3 = st.columns(3)
        c1.metric("Total events", len(user_logs))
        c2.metric(
            "Failed logins",
            sum(
                event["event_type"] == "FAILED_LOGIN"
                for event in user_logs
            ),
        )
        c3.metric(
            "Successful logins",
            sum(
                event["event_type"] == "SUCCESS_LOGIN"
                for event in user_logs
            ),
        )

        st.markdown("### Risk assessment")
        st.metric(
            "Risk score",
            f"{signals['risk_score']}/100",
            signals["risk_level"] + " risk",
        )
        st.progress(signals["risk_score"] / 100)

        for reason in signals["risk_reasons"]:
            st.write(f"- {reason}")

        st.markdown("### Detection findings")

        if user_alerts:
            for alert in user_alerts:
                st.warning(
                    f"{alert['severity']} — {alert['rule']}: "
                    f"{alert['details']}"
                )
                st.write(
                    "Recommended action: " + alert["recommendation"]
                )
                st.write(
                    f"MITRE ATT&CK: {alert['technique_id']} — "
                    f"{alert['technique_name']}"
                )
        else:
            st.success("No configured detection rules triggered.")

        st.markdown("### Login timeline")

        timeline_df = pd.DataFrame(user_logs).sort_values(
            "timestamp", ascending=False
        )
        timeline_df["timestamp"] = timeline_df["timestamp"].dt.strftime(
            TIME_FORMAT
        )

        st.dataframe(
            timeline_df,
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# INCIDENT REPORTS
# ============================================================

elif page == "Incident Reports":
    st.subheader("Incident report generator")

    if not accounts:
        st.info("No accounts available for reporting.")
    else:
        username = st.selectbox(
            "Select account for report",
            accounts,
            key="report_user",
        )

        report = make_incident_report(
            username,
            [
                event for event in logs
                if event["username"] == username
            ],
            alerts_by_user.get(username, []),
            account_signals[username],
        )

        st.text_area(
            "Report preview",
            value=report,
            height=420,
            disabled=True,
        )

        safe_name = "".join(
            char if char.isalnum() or char in "-_" else "_"
            for char in username
        )

        st.download_button(
            "Download incident report (.txt)",
            report,
            file_name=f"IdentityShield_Incident_{safe_name}.txt",
            mime="text/plain",
            use_container_width=True,
        )


# ============================================================
# MITRE ATT&CK
# ============================================================

elif page == "MITRE ATT&CK":
    st.subheader("MITRE ATT&CK technique mapping")

    st.write(
        "Mappings are hypotheses to guide investigation, not proof "
        "of attacker behavior."
    )

    st.markdown("### T1110 — Brute Force")
    st.write(
        "Repeated failed logins can be consistent with credential "
        "guessing; validate with other evidence."
    )
    st.markdown(
        "[Open the official MITRE ATT&CK T1110 reference]"
        "(https://attack.mitre.org/techniques/T1110/)"
    )

    mapping_df = pd.DataFrame([
        {
            "Detection rule": "Repeated failed logins",
            "Technique": "T1110",
            "Technique name": "Brute Force",
            "Confidence": "Potential match; validate evidence",
        },
        {
            "Detection rule": "Failures followed by success",
            "Technique": "T1110",
            "Technique name": "Brute Force",
            "Confidence": "Potential match; validate evidence",
        },
        {
            "Detection rule": "Multiple source IPs",
            "Technique": "Not directly mapped",
            "Technique name": "No direct mapping",
            "Confidence": "Insufficient evidence on its own",
        },
    ])

    st.dataframe(
        mapping_df,
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# INVESTIGATION ASSISTANT
# ============================================================

elif page == "Investigation Assistant":
    st.subheader("Investigation Assistant")
    st.caption(
        "Evidence-led support for the local training dataset. "
        "No AI model or containment actions are connected."
    )

    if not accounts:
        st.info("No accounts available to investigate.")
    else:
        username = st.selectbox(
            "Choose an account",
            accounts,
            key="assistant_user",
        )

        user_logs = sorted(
            [
                event for event in logs
                if event["username"] == username
            ],
            key=lambda event: event["timestamp"],
        )
        user_alerts = alerts_by_user.get(username, [])
        signals = account_signals[username]

        st.markdown("### Case summary")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Risk score", f"{signals['risk_score']}/100")
        c2.metric("Risk level", signals["risk_level"])
        c3.metric("Alerts", len(user_alerts))
        c4.metric(
            "Failed logins",
            sum(
                event["event_type"] == "FAILED_LOGIN"
                for event in user_logs
            ),
        )

        st.markdown("### Evidence and detection findings")

        if user_alerts:
            for alert in user_alerts:
                style = (
                    "alert-high"
                    if alert["severity"] == "HIGH"
                    else "alert-medium"
                )

                st.markdown(
                    f'<div class="alert-card {style}">'
                    f'<b>{escape(alert["severity"])} · '
                    f'{escape(alert["rule"])}</b><br>'
                    f'{escape(alert["details"])}<br>'
                    f'Source IP: {escape(alert["source_ip"])}<br>'
                    f'ATT&CK: {escape(alert["technique_id"])} — '
                    f'{escape(alert["technique_name"])}<br>'
                    f'Recommendation: {escape(alert["recommendation"])}'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info(
                "No configured detection rules triggered for this account."
            )

        st.markdown("### Evidence timeline")

        timeline_df = pd.DataFrame(user_logs).sort_values(
            "timestamp", ascending=False
        )
        timeline_df["timestamp"] = timeline_df["timestamp"].dt.strftime(
            TIME_FORMAT
        )

        st.dataframe(
            timeline_df,
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("### Analyst review checklist")

        checklist = [
            "Reviewed the full login timeline",
            "Checked whether source IP addresses are expected",
            "Verified the successful login with the account owner, if applicable",
            "Looked for supporting evidence before concluding an attack",
            "Followed escalation procedure, if applicable",
        ]

        checked = []

        check_columns = st.columns(2)

        for index, item in enumerate(checklist):
            with check_columns[index % 2]:
                if st.checkbox(
                    item,
                    key=f"check_{username}_{index}",
                ):
                    checked.append(item)

        assessment = st.selectbox(
            "Current case assessment",
            [
                "Open - needs investigation",
                "Likely benign - verify before closing",
                "Suspicious - escalate for review",
                "Insufficient evidence",
            ],
            key=f"assessment_{username}",
        )

        notes = st.text_area(
            "Analyst notes",
            placeholder=(
                "Record evidence reviewed, questions to resolve, "
                "and next steps..."
            ),
            key=f"notes_{username}",
            height=120,
        )

        worksheet = [
            "IDENTITYSHIELD AI - INVESTIGATION WORKSHEET",
            "=" * 52,
            f"Generated: {datetime.now().strftime(TIME_FORMAT)}",
            "Data source: Local CSV or built-in simulated sample data",
            "Project status: Rule-based educational prototype",
            "",
            f"Account: {username}",
            f"Assessment: {assessment}",
            f"Risk score: {signals['risk_score']}/100",
            f"Risk level: {signals['risk_level']}",
            f"Total events: {len(user_logs)}",
            f"Alerts: {len(user_alerts)}",
            "",
            "RISK SIGNALS",
            *[
                f"- {reason}"
                for reason in signals["risk_reasons"]
            ],
            "",
            "DETECTION FINDINGS",
        ]

        if user_alerts:
            for alert in user_alerts:
                worksheet.extend([
                    f"- {alert['severity']}: {alert['rule']}",
                    f"  Details: {alert['details']}",
                    f"  Source IP: {alert['source_ip']}",
                    (
                        f"  ATT&CK: {alert['technique_id']} — "
                        f"{alert['technique_name']}"
                    ),
                    f"  Mapping note: {alert['mapping_note']}",
                    f"  Recommended action: {alert['recommendation']}",
                ])
        else:
            worksheet.append("- No configured detection rules triggered.")

        worksheet.extend([
            "",
            "ANALYST CHECKLIST",
            *[
                f"[{'x' if item in checked else ' '}] {item}"
                for item in checklist
            ],
            "",
            "ANALYST NOTES",
            notes.strip() or "No notes entered.",
            "",
            "LIMITATIONS",
            "- Rule-based results are signals for review, not proof of compromise.",
            "- No AI model, live SIEM, or external threat-intelligence source is connected.",
            "- No containment actions are performed by this worksheet.",
        ])

        safe_name = "".join(
            char if char.isalnum() or char in "-_" else "_"
            for char in username
        )

        st.download_button(
            "Download investigation worksheet (.txt)",
            "\n".join(worksheet),
            file_name=f"IdentityShield_Investigation_{safe_name}.txt",
            mime="text/plain",
            use_container_width=True,
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()
st.caption(
    "IDENTITYSHIELD AI · EDUCATIONAL SOC ANALYST LAB · "
    "RULE-BASED DETECTION · SIMULATED/LOCAL DATA"
)