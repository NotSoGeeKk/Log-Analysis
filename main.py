import csv
from collections import Counter, defaultdict

# File paths
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(log_file):
    """Parse the log file and extract relevant information."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    with open(log_file, "r") as file:
        for line in file:
            parts = line.split()
            if len(parts) < 9:
                continue  # Skip malformed lines

            ip = parts[0]
            request_info = parts[5:7]  # Method and endpoint
            status_code = parts[8]
            message = " ".join(parts[9:]).strip('"')

            # Extract IP and request counts
            ip_requests[ip] += 1

            # Extract endpoint counts
            endpoint = request_info[1] if len(request_info) > 1 else None
            if endpoint:
                endpoint_requests[endpoint] += 1

            # Detect failed logins
            if status_code == "401" or "Invalid credentials" in message:
                failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def write_to_csv(ip_requests, most_accessed, suspicious_activity, output_file):
    """Write analysis results to a CSV file."""
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)

        # Write IP request counts
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    # Parse the log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)

    # Identify most accessed endpoint
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]

    # Filter suspicious activity based on threshold
    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    # Display results
    print("\nRequests per IP:")
    print("IP Address           Request Count")
    for ip, count in ip_requests.most_common():
        print(f"{ip:20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:20} {count}")
    else:
        print("No suspicious activity detected.")

    # Write results to CSV
    write_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
