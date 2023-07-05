import requests
import logging
import colorlog
import time

BASE_URL = "https://discord.com/api/v9/users/@me"
REQUEST_HEADERS = {
    "Content-Type": "application/json",
    "Origin": "https://discord.com",
    "Authorization": "your discord token",
}

# Configure colorlog and logging
colorlog.basicConfig(
    level=logging.INFO, format="%(log_color)s[%(levelname)s] %(message)s"
)
logger = colorlog.getLogger()

# Read usernames from the file
with open("usernames.txt", "r") as file:
    usernames = file.read().splitlines()

# Iterate through each username
for username in usernames:
    # Payload data
    payload = {"username": username, "password": "your discord account password"}

    while True:
        # Send PATCH request
        response = requests.patch(BASE_URL, headers=REQUEST_HEADERS, json=payload)

        # Check if username is available
        if response.status_code == 200:
            logger.info(f"Username '{username}' is available")
            # Save available username to "halal.txt" file
            with open("halal.txt", "a") as file:
                file.write(username + "\n")
            break  # Move to the next username

        elif response.status_code == 400:
            response_json = response.json()
            if "username" in response_json.get("errors", {}):
                username_error = response_json["errors"]["username"]["_errors"][0][
                    "code"
                ]
                if username_error == "USERNAME_ALREADY_TAKEN":
                    logger.warning(f"Username '{username}' is already taken")
                    break  # Move to the next username
                elif username_error == "USERNAME_RATE_LIMIT":
                    retry_after = response.headers.get("Retry-After")
                    if retry_after is not None:
                        retry_seconds = int(retry_after)
                        logger.error(
                            f"Rate limited. Retrying username '{username}' in {retry_seconds} seconds"
                        )
                        time.sleep(retry_seconds)
                        continue  # Retry the same username
                    else:
                        logger.error(
                            f"Rate limited. Retry duration not provided for username '{username}'"
                        )
                        break  # Move to the next username
                else:
                    logger.warning(f"Invalid username '{username}'")
            elif "captcha_key" in response_json:
                logger.info(f"Username '{username}' is available (Captcha required)")
                # Save available username to "halal.txt" file
                with open("halal.txt", "a") as file:
                    file.write(username + "\n")
                break  # Move to the next username
            else:
                logger.warning(
                    f"Invalid form body for username '{username}'. Response: {response.text}"
                )
                break  # Move to the next username
        elif response.status_code == 401:
            logger.error(
                f"Unauthorized. Invalid authorization token for username '{username}'"
            )
            break  # Move to the next username
        elif response.status_code == 500:
            logger.error(f"Internal Server Error for username '{username}'")
            break  # Move to the next username
        else:
            retry_after = response.headers.get("Retry-After")
            if retry_after is not None:
                retry_seconds = int(retry_after)
                logger.error(
                    f"Unknown error occurred. Retrying username '{username}' in {retry_seconds} seconds"
                )
                time.sleep(retry_seconds)
                continue  # Retry the same username
            else:
                logger.error(
                    f"Unknown error occurred for username '{username}' Response: {response.text}"
                )
                break  # Move to the next username

    time.sleep(2)  # Pause for 2 seconds before checking the next username

# Logging the result
logger.info("Available usernames are saved in 'halal.txt' file.")
