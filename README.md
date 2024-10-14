# APRS Bot

APRS Bot is a Python-based application that interacts with the Automatic Packet Reporting System (APRS) using the KISS protocol. It connects to a Direwolf KISS TCP interface to send and receive APRS packets.

## Features

- Connects to Direwolf KISS TCP interface
- Constructs and validates AX.25 frames
- Sends and receives APRS packets
- Handles various commands such as `WHEREAMI`, `ISS_LOCATION`, `SKGWEATHER`, `ECHO`, and `HELP`
- Fetches weather data from OpenWeatherMap API

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/aprs_bot.git
    cd aprs_bot
    ```

2. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

3. Update the `constants.py` file with your actual values for `API_KEY`, `CALLSIGN`, and `SSID`.

## Usage

1. Start the Direwolf KISS TCP interface on port 8001.

2. Run the APRS Bot:
    ```sh
    python3 aprs_bot.py
    ```

## Configuration

The configuration constants are defined in the [constants.py](constants.py) file:

```python
KISS_FEND = 0xC0  # KISS Frame Delimiter
KISS_DATA_FRAME = 0x00  # KISS data frame identifier
KISS_PORT = 8001  # Direwolf KISS TCP port
API_KEY = 'your_openweathermap_api_key'  # Replace with your actual API key
CALLSIGN = 'your_callsign'  # Replace with your actual callsign
SSID = 2  # Replace with your actual SSID