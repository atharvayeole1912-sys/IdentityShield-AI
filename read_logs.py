
import csv
from datetime import datetime, timedelta

account_events = {}

# Read simulated login records
with open("data/login_logs.csv", "r", newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:
        username = row["username"]
        account_events.setdefault(username, []).append(row)

print("========================================")
print("          IDENTITYSHIELD AI")
print("     LOGIN THREAT INVESTIGATION")
print("========================================")

accounts_investigated = 0
accounts_with_alerts = 0
high_alerts = 0
medium_alerts = 0


def show_recommendations():
    print("\nWhat should the analyst do?")
    print("1. Check if the user really logged in.")
    print("2. Check the user's previous login activity.")
    print("3. Check if the IP address is familiar.")
    print("4. Tell the senior analyst if anything looks suspicious.")


for username, events in account_events.items():
    accounts_investigated += 1
    account_has_alert = False
    ip_events = {}

    # Group events by source IP
    for event in events:
        ip = event["source_ip"]
        ip_events.setdefault(ip, []).append(event)

    print("\n----------------------------------------")
    print("Account:", username)

    # Check for multiple source IPs
    if len(ip_events) > 1:
        print("MEDIUM ALERT: Multiple source IPs detected.")
        medium_alerts += 1
        account_has_alert = True

    # Investigate each source IP
    for ip, related_events in ip_events.items():
        related_events.sort(
            key=lambda event: datetime.strptime(
                event["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
        )

        failed_times = []
        success_times = []

        for event in related_events:
            event_time = datetime.strptime(
                event["timestamp"], "%Y-%m-%d %H:%M:%S"
            )

            if event["event_type"] == "FAILED_LOGIN":
                failed_times.append(event_time)
            elif event["event_type"] == "SUCCESS_LOGIN":
                success_times.append(event_time)

        print("\nSource IP:", ip)
        print("Failed logins:", len(failed_times))
        print("Successful logins:", len(success_times))

        # Rule 1: Three failures followed by success within five minutes
        suspicious_sequence = False

        for success_time in success_times:
            failures_before_success = [
                failed_time for failed_time in failed_times
                if success_time - timedelta(minutes=5)
                <= failed_time < success_time
            ]

            if len(failures_before_success) >= 3:
                suspicious_sequence = True
                break

        if suspicious_sequence:
            print("\nHIGH ALERT: Failed logins followed by success!")
            print("Account:", username)
            print("Source IP:", ip)
            print("Severity: HIGH")
            show_recommendations()
            high_alerts += 1
            account_has_alert = True

        # Rule 2: Three or more failures within five minutes
        repeated_failures = False

        for start_index in range(len(failed_times)):
            window_start = failed_times[start_index]
            window_end = window_start + timedelta(minutes=5)

            count = sum(
                1 for timestamp in failed_times
                if window_start <= timestamp <= window_end
            )

            if count >= 3:
                repeated_failures = True
                break

        if repeated_failures and not suspicious_sequence:
            print("\nHIGH ALERT: Repeated failed logins!")
            print("Account:", username)
            print("Source IP:", ip)
            print("Severity: HIGH")
            show_recommendations()
            high_alerts += 1
            account_has_alert = True

    # Display final account status
    print("\nAccount status:")

    if account_has_alert:
        print("NEEDS INVESTIGATION")
    else:
        print("NORMAL")

    if account_has_alert:
        accounts_with_alerts += 1

# Final summary
print("\n========================================")
print("             ALERT SUMMARY")
print("========================================")
print("Accounts investigated:", accounts_investigated)
print("Accounts needing investigation:", accounts_with_alerts)
print("High-severity alerts:", high_alerts)
print("Medium-severity alerts:", medium_alerts)
print("Investigation completed.")
