import requests
import subprocess
import os
import sqlite3
import pytz
import tempfile
import shutil
from datetime import datetime
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Slack client
slack_token = os.getenv('slack_bot_token')
client = WebClient(token=slack_token)
slack_channel = os.getenv('slack_channel')
namespace = os.getenv('namespace')

# Database initialization
def initialize_db():
    conn = sqlite3.connect('images.db')
    cursor = conn.cursor()
    # Create the images table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS images (
                        image_name TEXT,
                        tag TEXT,
                        digest TEXT,
                        last_updated_image_timestamp TEXT,
                        vulnerabilities_count INTEGER,
                        PRIMARY KEY (image_name, tag))''')
    # Check if columns digest and vulnerabilities_count exist
    cursor.execute("PRAGMA table_info(images)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'digest' not in columns:
        cursor.execute("ALTER TABLE images ADD COLUMN digest TEXT")
    if 'vulnerabilities_count' not in columns:
        cursor.execute("ALTER TABLE images ADD COLUMN vulnerabilities_count INTEGER")
    conn.commit()
    conn.close()

# Fetch all repositories from the namespace
def get_all_repositories(namespace):
    repos = []
    url = f"https://hub.docker.com/v2/repositories/{namespace}/"
    params = {'page_size': 100}
    while url:
        response = requests.get(url, params=params)
        if response.status_code != 200:
            print(f"Error fetching repositories: {response.status_code}")
            break
        data = response.json()
        repos.extend([repo['name'] for repo in data.get('results', [])])
        url = data.get('next')
        params = {}
    return repos

# Fetch all tags for a specific repository
def get_all_tags(namespace, repository):
    tags = []
    url = f"https://hub.docker.com/v2/repositories/{namespace}/{repository}/tags/"
    params = {'page_size': 100}
    while url:
        response = requests.get(url, params=params)
        if response.status_code != 200:
            print(f"Error fetching tags for {repository}: {response.status_code}")
            break
        data = response.json()
        tags.extend([tag['name'] for tag in data.get('results', [])])
        url = data.get('next')
        params = {}
    return tags

# Get the image digest from Docker Registry API
def get_image_digest(namespace, repository, tag):
    # Get the authentication token
    token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{namespace}/{repository}:pull"
    token_response = requests.get(token_url)
    #print(f"Token request status code: {token_response.status_code}")
    #print(f"Token response content: {token_response.text}")
    if token_response.status_code != 200:
        print(f"Error fetching token for {namespace}/{repository}:{tag}: {token_response.status_code}")
        return None
    token = token_response.json().get('token')
    if not token:
        print(f"No token found for {namespace}/{repository}:{tag}")
        return None

    # Send a HEAD request to get the digest
    manifest_url = f"https://registry-1.docker.io/v2/{namespace}/{repository}/manifests/{tag}"
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.docker.distribution.manifest.v2+json'
    }
    response = requests.head(manifest_url, headers=headers)
    # print(f"Digest request status code: {response.status_code}")
    # print(f"Digest response headers: {response.headers}")
    if response.status_code != 200:
        print(f"Error fetching digest for {namespace}/{repository}:{tag}: {response.status_code}")
        return None
    digest = response.headers.get('Docker-Content-Digest')
    # print(f"Digest for {namespace}/{repository}:{tag}: {digest}")
    return digest


# Update image information in the database
def update_db(image_name, tag, digest, vulnerabilities_count):
    conn = sqlite3.connect('images.db')
    cursor = conn.cursor()
    # Get current time in IST
    ist = pytz.timezone('Asia/Kolkata')
    current_time_ist = datetime.now(ist).strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute('''INSERT OR REPLACE INTO images (image_name, tag, digest, last_updated_image_timestamp, vulnerabilities_count)
                      VALUES (?, ?, ?, ?, ?)''', (image_name, tag, digest, current_time_ist, vulnerabilities_count))
    conn.commit()
    conn.close()

# Send a Slack message
def send_message_to_slack(message):
    try:
        response = client.chat_postMessage(
            channel=slack_channel,
            text=message
        )
        print("Message sent to Slack successfully.")
    except SlackApiError as e:
        print(f"Error sending message to Slack: {e.response['error']}")

# TruffleHog scan on extracted filesystem
def run_trufflehog(image_tag):
    print(f"Running TruffleHog on extracted filesystem of {image_tag}")
    temp_dir = tempfile.mkdtemp()
    container_name = f"temp_container_{image_tag.replace('/', '_').replace(':', '_')}"
    vulnerabilities_count = 0
    try:
        # Pull the image with platform specification
        subprocess.run(['docker', 'pull', '--platform', 'linux/amd64', image_tag], check=True)

        # Create a temporary container with platform specification
        subprocess.run(['docker', 'create', '--platform', 'linux/amd64', '--name', container_name, image_tag], check=True)

        # Export the container's filesystem and extract it to the temp directory
        export_cmd = ['docker', 'export', container_name]
        with subprocess.Popen(export_cmd, stdout=subprocess.PIPE) as proc:
            with subprocess.Popen(['tar', '-x', '-C', temp_dir], stdin=proc.stdout) as tar_proc:
                proc.stdout.close()
                tar_proc.communicate()

        # First Run: Generate human-readable output for Slack
        command = ['trufflehog', 'filesystem', temp_dir, '--only-verified']
        result = subprocess.run(command, capture_output=True, text=True)
        scan_results = result.stdout

        # Second Run: Generate JSON output for counting vulnerabilities
        command_json = ['trufflehog', 'filesystem', temp_dir, '--only-verified', '--json']
        result_json = subprocess.run(command_json, capture_output=True, text=True)
        scan_results_json = result_json.stdout

        # Parse JSON lines and count vulnerabilities
        vulnerabilities_count = 0
        for line in scan_results_json.strip().split('\n'):
            if line.strip():
                vulnerabilities_count += 1  # Each JSON line represents a finding

    except subprocess.CalledProcessError as e:
        print(f"Error during scanning {image_tag}: {e}")
        scan_results = f"Error during scanning {image_tag}: {e}"
    finally:
        # Clean up: remove temporary container and directory
        subprocess.run(['docker', 'rm', container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(temp_dir)
    return scan_results, vulnerabilities_count


# Main function
def scan_images(namespace):
    initialize_db()

    repos = get_all_repositories(namespace)
    images_to_scan = []  # List of images that need to be scanned

    for repo in repos:
        tags = get_all_tags(namespace, repo)
        for tag in tags:
            image_name = repo
            # Get the digest for the image:tag
            digest = get_image_digest(namespace, repo, tag)
            if digest is None:
                continue  # Skip if we couldn't get the digest
            # Get the stored digest from the database
            conn = sqlite3.connect('images.db')
            cursor = conn.cursor()
            cursor.execute('SELECT digest FROM images WHERE image_name=? AND tag=?', (image_name, tag))
            result = cursor.fetchone()
            conn.close()
            if result:
                stored_digest = result[0]
            else:
                stored_digest = None
            if digest != stored_digest:
                # Image is new or updated, need to scan
                images_to_scan.append((repo, tag, digest))
            else:
                print(f"No changes detected for {image_name}:{tag}, skipping scan.")

    if images_to_scan:
        # Slack message: Number of images and tags to be scanned
        message = (f"Number of Public Docker images to be scanned: {len(images_to_scan)}.\nScan started at {datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S')} IST.")
        send_message_to_slack(message)

        # Start scanning each image:tag and send results to Slack
        for repo, tag, digest in images_to_scan:
            image_tag = f"{namespace}/{repo}:{tag}"
            scan_results, vulnerabilities_count = run_trufflehog(image_tag)

            # Update the database with new digest and vulnerabilities_count
            update_db(repo, tag, digest, vulnerabilities_count)

            # Slack message for each scan
            if vulnerabilities_count > 0:
                scan_message = (f":alert: TruffleHog found {vulnerabilities_count} vulnerabilities in {repo}:{tag}.\nVerified results are:\n```\n{scan_results}\n```")
            else:
                scan_message = f"No vulnerabilities found in {repo}:{tag}."
            send_message_to_slack(scan_message)
    else:
        print("No new or updated images to scan.")

if __name__ == "__main__":
    scan_images(namespace)
