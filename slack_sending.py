#!/usr/bin/env python3
import os
import argparse
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Slack client
slack_token = os.getenv('slack_bot_token')  # Slack bot token from environment variables
client = WebClient(token=slack_token)
slack_channel = os.getenv('slack_channel')  # Slack channel ID from environment variables

# Function to send a file to Slack
def send_file_to_slack(filepath: str, repo_name: str):
    try:
        print(f"Preparing to send file {filepath} for {repo_name}")
        if os.path.exists(filepath):
            result = client.files_upload(
                channels=slack_channel,
                file=filepath,
                title=f"TruffleHog results for {repo_name}",
            )
            print(f"File {filepath} sent to Slack channel {slack_channel}")
        else:
            print(f"Error: File {filepath} does not exist.")
    except SlackApiError as e:
        print(f"Error sending file to Slack: {e.response['error']}")
        print(f"Full response: {e.response}")

# Function to send a summary message to Slack
def send_summary_to_slack(file_list: list):
    try:
        number_of_files = len(file_list)
        file_names = "\n".join([f"`Trufflehog result for {os.path.basename(file)}`" for file in file_list])
        summary_message = f"Trufflehog Scan started on {number_of_files} images.\n{file_names}"
        
        print(f"Attempting to send summary message to Slack...")
        response = client.chat_postMessage(
            channel=slack_channel,
            text=summary_message
        )
        print("Summary message sent to Slack successfully.")
    except SlackApiError as e:
        print(f"Error sending message to Slack: {e.response['error']}")
        print(f"Full response: {e.response}")

# Function to send a basic message to Slack
def send_message_to_slack(message: str):
    try:
        print(f"Attempting to send message: {message}")
        response = client.chat_postMessage(
            channel=slack_channel,
            text=message
        )
        print("Message sent to Slack successfully.")
    except SlackApiError as e:
        print(f"Error sending message to Slack: {e.response['error']}")
        print(f"Full response: {e.response}")

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Send files or a message to Slack.')
    subparsers = parser.add_subparsers(dest='command', help='Sub-commands: send_files, send_summary, send_message')

    # Sub-parser for sending files
    parser_files = subparsers.add_parser('send_files', help='Send multiple files to Slack.')
    parser_files.add_argument('file_paths', nargs='+', type=str, help='Paths to the files to send')

    # Sub-parser for sending summary messages
    parser_summary = subparsers.add_parser('send_summary', help='Send a summary message to Slack.')
    parser_summary.add_argument('file_list', nargs='+', type=str, help='List of scanned file paths')

    # Sub-parser for sending plain messages
    parser_message = subparsers.add_parser('send_message', help='Send a plain message to Slack.')
    parser_message.add_argument('message', type=str, help='Message to send')

    # Parse the arguments
    args = parser.parse_args()

    if args.command == 'send_files':
        for file_path in args.file_paths:
            file_path = os.path.abspath(file_path)
            # Check if the provided file exists
            if not os.path.isfile(file_path):
                print(f"Error: The file {file_path} does not exist.")
                continue
            repo_name = os.path.basename(file_path).split('_th_results.txt')[0]
            send_file_to_slack(file_path, repo_name)
    
    elif args.command == 'send_summary':
        send_summary_to_slack(args.file_list)
    
    elif args.command == 'send_message':
        send_message_to_slack(args.message)

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
