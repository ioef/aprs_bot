import socket
import logging
import time
import re
import requests
import queue
from datetime import datetime
from constants import KISS_FEND, KISS_PORT, KISS_DATA_FRAME, API_KEY, CALLSIGN, SSID
from astral import LocationInfo
from astral.sun import sun
import tips_of_the_day
import random

# Configure logging
logging.basicConfig(filename='aprs_bot.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class APRSBot:
    def __init__(self, src_call, src_ssid, port=KISS_PORT):
        self.src_call = CALLSIGN
        self.src_ssid = SSID
        self.port = port
        self.sock = None
        self.message_queue = queue.Queue()

    def create_ax25_address(self, call_sign, ssid, last=False):
        """
        Create AX.25 address bytes from call sign and SSID.
        Args:
            call_sign (str): The call sign.
            ssid (int): The SSID (0-15).
            last (bool): Whether this is the last address in the path.
        Returns:
            bytearray: The AX.25 address bytes.
        """
        call_sign = call_sign.upper().ljust(6)[:6]  # Normalize and pad call sign to 6 characters
        call_sign_bytes = bytearray(call_sign.encode('ascii'))
        ssid_byte = (ssid << 1) | 0x60
        if last:
            ssid_byte |= 0x01

        address = bytearray()
        for byte in call_sign_bytes:
            address.append(byte << 1)
        address.append(ssid_byte)

        #logging.debug(f'Created AX.25 address: {call_sign} with SSID {ssid} => {address.hex()}')
        return address

    def validate_ax25_frame(self, kiss_frame):
        """
        Validate the constructed AX.25 frame.
        Args:
            kiss_frame (bytearray): The KISS frame to validate.
        Returns:
            bool: True if valid, False otherwise.
        """
        if kiss_frame[0] != KISS_FEND or kiss_frame[-1] != KISS_FEND:
            logging.error('Frame does not start and end with KISS FEND.')
            return False

        if len(kiss_frame) < 7:  # Minimum frame length (including FENDs)
            logging.error('Frame too short to be valid AX.25.')
            return False

        logging.info('Frame is valid AX.25.')
        return True

    def build_kiss_frame(self, src_call, src_ssid, dest_call, dest_ssid, digi_calls, aprs_payload):
        """
        Build a KISS frame for an AX.25 packet.

        Args:
            src_call (str): Source call sign.
            src_ssid (int): Source SSID.
            dest_call (str): Destination call sign.
            dest_ssid (int): Destination SSID.
            digi_calls (list): List of digipeater callsigns and ssids.
            aprs_payload (bytes): Payload for the APRS message.

        Returns:
            bytearray: The constructed KISS frame.
        """
        dest_address = self.create_ax25_address(dest_call, dest_ssid)
        src_address = self.create_ax25_address(src_call, src_ssid)

        digi_addresses = []
        for i, (digi_call, digi_ssid) in enumerate(digi_calls):
            last = (i == len(digi_calls) - 1)
            digi_addresses.append(self.create_ax25_address(digi_call, digi_ssid, last))

        kiss_frame = bytearray([KISS_FEND])  # Start with Frame delimiter
        kiss_frame.append(KISS_DATA_FRAME)   # Append KISS command/data frame byte
        kiss_frame.extend(dest_address)      # Append Destination Address
        kiss_frame.extend(src_address)       # Append Source Address
        for addr in digi_addresses:
            kiss_frame.extend(addr)          # Append Digipeater Addresses
        kiss_frame.extend(bytearray([0x03])) # Control Field (UI frame)
        kiss_frame.extend(bytearray([0xF0])) # Protocol Identifier

        # Append the payload
        kiss_frame.extend(aprs_payload)      # Append the payload
        kiss_frame.append(KISS_FEND)         # End with Frame delimiter

        # Validate the KISS frame
        if not self.validate_ax25_frame(kiss_frame):
            logging.error("Invalid KISS frame constructed.")
            return None

        return kiss_frame
    
    def send_packet(self, dest_call, dest_ssid, aprs_payload):
        """
        Send the constructed KISS frame to the Direwolf KISS TCP interface.
        Args:
            dest_call (str): Destination call sign.
            dest_ssid (int): Destination SSID.
            aprs_payload (bytes): Payload for the APRS message.
        """
        digi_calls = [("WIDE1", 1), ("WIDE2", 2)]  # List of digipeater callsigns and ssids
        kiss_frame = self.build_kiss_frame(self.src_call, self.src_ssid, dest_call, dest_ssid, digi_calls, aprs_payload)
        logging.info(kiss_frame)
        if kiss_frame is None:
            return

        try:
            self.sock.sendall(kiss_frame)
            logging.info("Packet sent successfully.")
        except Exception as e:
            logging.error(f"Error sending packet: {e}")

    def connect(self):
        """Connect to Direwolf on localhost:8001."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(('localhost', self.port))
            logging.info("Connected to Direwolf on localhost:8001")
        except Exception as e:
            logging.error(f"Failed to connect to Direwolf: {e}")
            self.sock = None

    def receive_packet(self):
        """Receive packets from Direwolf and enqueue them."""
        try:
            data = self.sock.recv(1024)
            if data:
                logging.info(f"Received packet: {data}")
                self.message_queue.put(data)  # Enqueue the received data
        except Exception as e:
            logging.error(f"Error receiving packet: {e}")

    def process_message_queue(self):
        """Process messages from the queue."""
        while not self.message_queue.empty():
            packet = self.message_queue.get()
            src_callsign, src_ssid, dst_callsign, dst_ssid, message = self.parse_packet(packet)
            if src_callsign and message:
                own_call = f"{self.src_call}-{self.src_ssid}"
                recipient = f"{dst_callsign}-{dst_ssid}"
                if recipient != own_call:
                    continue
                self.handle_message(src_callsign, src_ssid, message, dst_callsign, dst_ssid)

    def decode_ax25_address(self, encoded_bytes):
        """
        Decodes a 7-byte AX.25 address (callsign + SSID).
        Args:
        encoded_bytes (bytes): 7 bytes representing the AX.25 address.

        Returns:
        tuple: (callsign, ssid) as a string and an integer.
        """
        callsign_bytes = bytearray([byte >> 1 for byte in encoded_bytes[:6]])
        callsign = callsign_bytes.decode('ascii').strip()  # Remove padding spaces

        # Decode the SSID (stored in the last byte, after the callsign)
        ssid = (encoded_bytes[6] >> 1) & 0x0F  # Extract SSID (bits 1-4)
        return callsign, ssid

    def extract_addresses_and_message(self, packet_bytes):
        packet_bytes = packet_bytes.strip(b'\xc0')  # Remove KISS framing
        packet_bytes = packet_bytes.replace(b'\r', b'')  # Remove carriage return

        # Extract source address from AX.25 frame (8-15 bytes)
        src_addr = self.decode_ax25_address(packet_bytes[8:15])  # Correct byte range for sender
        sender_callsign, sender_ssid = src_addr

        payload_start = packet_bytes.find(b':')  # Start of message payload
        message_payload = packet_bytes[payload_start:].decode('utf-8').strip() if payload_start != -1 else ""

        # Extract the receiver callsign and receiver ssid after the first colon and before the second colon
        parts = message_payload.split(':')
        if len(parts) > 2:
            receiver_callsign_ssid = parts[1].strip()
            if '-' in receiver_callsign_ssid:
                receiver_callsign, receiver_ssid = receiver_callsign_ssid.split('-')
                message = parts[2].strip()
            else:
                return sender_callsign, sender_ssid, "", "", ""
        else:
            return sender_callsign, sender_ssid, "", "", ""

        return sender_callsign, sender_ssid, receiver_callsign, receiver_ssid, message


    def parse_packet(self, packet):
        """Parse received APRS packet to extract sender, receiver, and message."""
        try:
            # Extract source and destination addresses
            sender_callsign, sender_ssid, receiver_callsign, receiver_ssid, message = self.extract_addresses_and_message(packet)
            logging.info(f"Sender: {sender_callsign}-{sender_ssid} Receiver: {receiver_callsign}-{receiver_ssid} Message: {message}")
        except Exception as e:
            logging.error(f"Error parsing packet: {e}")
            return None, None, None, None, None
        return sender_callsign, sender_ssid, receiver_callsign, receiver_ssid, message


    def fetch_weather(self, CITY='Thessaloniki'):
        # Fetch weather data from an online API (example: OpenWeatherMap)
        url = f"http://api.openweathermap.org/data/2.5/weather?q={CITY}&appid={API_KEY}&units=metric"
        try:
            response = requests.get(url)
            weather_data = response.json()
            if weather_data.get("cod") != 200:
                logging.error(f"Failed to fetch weather data: {weather_data.get('message')}")
                return None
            weather_info = f"Weather in {CITY}: {weather_data['main']['temp']} deg C, {weather_data['weather'][0]['description']}"
            return weather_info
        except Exception as e:
            logging.error(f"Error fetching weather data: {e}")
            return None

    def fetch_iss_location(self):
        """Fetch the current location of the ISS."""
        url = "http://api.open-notify.org/iss-now.json"
        try:
            response = requests.get(url)
            data = response.json()
            if data['message'] == 'success':
                position = data['iss_position']
                latitude = position['latitude']
                longitude = position['longitude']
                return f"{latitude} N, {longitude} W"
            else:
                return "Could not retrieve ISS location"
        except Exception as e:
            logging.error(f"Error fetching ISS location: {e}")
            return "Error fetching ISS location"

    def fetch_astros_in_space(self):
        """Fetch the current astronauts in space."""
        url = "http://api.open-notify.org/astros.json"
        try:
            response = requests.get(url)
            data = response.json()
            if data['message'] == 'success':
                astros = [astro['name'] for astro in data['people']]
                return ', '.join(astros)
            else:
                return "Could not retrieve astronaut data"
        except Exception as e:
            logging.error(f"Error fetching astronaut data: {e}")
            return "Error fetching astronaut data"

    def get_sun_times(self, city_name):
        """
        Get sunrise and sunset times for a given city.
        Args:
            city_name (str): The name of the city.
        Returns:
            dict: A dictionary with sunrise and sunset times.
        """
        city = LocationInfo(city_name)
        s = sun(city.observer, date=datetime.now())
        return {
            'sunrise': s['sunrise'].strftime('%H:%M:%S'),
            'sunset': s['sunset'].strftime('%H:%M:%S')
        }

    def handle_message(self, callsign, ssid, message, dst_callsign=None, dst_ssid=None):
        """Handle different messages and respond accordingly."""

        match = re.search(r'\{(\d+)\s*$', message)  # Match any { followed by digits at the end
        if match:
            ack_number = match.group(1)
            ack_message = f":{callsign}-{ssid}: ack{ack_number}"
            self.send_packet(callsign, ssid, ack_message.encode('utf-8'))
            time.sleep(1.2)
        if "WHEREMAI" in message.upper():
            self.send_whereami(callsign, ssid)
        elif "ISS_LOCATION" in message.upper():
            self.send_iss_location(callsign, ssid)
        elif "ISS_ASTROS" in message.upper():
            self.send_astros(callsign, ssid)
        elif "SKGWEATHER" in message.upper():
            self.send_weather_skg(callsign, ssid)
        elif "WEATHER?" in message.upper():
            city = message.split('?')[1].split()[0]
            city = re.sub(r"\{\d+", "", city)
            self.send_weather_generic(callsign, ssid, city)
        elif "TIP" in message.upper():
            self.send_tips(callsign, ssid)
        elif "REPEATERS" in message.upper():
            repeaters = "SV2A 145.750,SV2D 145.675 88.5Hz,SV2O 145.600 94.8Hz"
            self.send_packet(callsign, ssid, f":{callsign}-{ssid}: {repeaters}".encode('utf-8'))
        elif "SUNRISE" in message.upper():
            sun_times = self.get_sun_times("Thessaloniki")
            self.send_packet(callsign, ssid, f":{callsign}-{ssid}: Sunrise: {sun_times['sunrise']} Sunset: {sun_times['sunset']}".encode('utf-8'))
        elif "BEACON" in message.upper():
            message = "QSL. Signal received loud and clear! 73!"
            self.send_beacon(callsign, ssid, message)
        elif "HELP" in message.upper():
            self.send_help(callsign, ssid)
        else:
            logging.info(f"Unknown command received from {callsign}-{ssid}: {message}")
            self.send_unknown(callsign, ssid)

    def send_whereami(self, callsign, ssid):
        """Respond with dummy location data."""
        location = "Your location: 40.7128 N, 74.0060 W"
        self.send_packet(callsign, ssid, f":{callsign}-{ssid}: {location} 73!".encode('utf-8'))

    def send_iss_location(self, callsign, ssid):
        """Respond with dummy ISS location data."""
        iss_location = self.fetch_iss_location()
        self.send_packet(callsign, ssid, f":{callsign}-{ssid}: ISS Location {iss_location}".encode('utf-8'))
        
    def send_astros(self, callsign, ssid):
        """Respond with dummy astronaut data."""
        astros = self.fetch_astros_in_space()
        self.send_packet(callsign, ssid, f":{callsign}-{ssid}: {astros}".encode('utf-8'))

    def send_weather_skg(self, callsign, ssid):
        """Respond with dummy weather data for Thessaloniki."""
        weather_info = self.fetch_weather()
        self.send_packet(callsign, ssid, f":{callsign}-{ssid}: {weather_info}".encode('utf-8'))

    def send_weather_generic(self, callsign, ssid, city):
        """Respond with dummy weather data for Thessaloniki."""
        weather_info = self.fetch_weather(city)
        self.send_packet(callsign, ssid, f":{callsign}-{ssid}: {weather_info}".encode('utf-8'))
    
    def send_tips(self, callsign, ssid):
        """Respond with a tip."""
        #tips of the day is a dictionary with tips.
        #randomize and select a tip to send
        #get a number from 0 to 227 and select the tip with that number
        tip_index = random.randint(0, len(tips_of_the_day.tips_of_the_day) - 1)
        tip = tips_of_the_day.tips_of_the_day[tip_index]
        self.send_packet(callsign, ssid, f":{callsign}-{ssid}: {tip}".encode('utf-8'))

    def send_beacon(self, callsign, ssid, message):
        """Send a beacon message."""
        self.send_packet(callsign, ssid, f":{callsign}-{ssid}: {message}".encode('utf-8'))

    def send_help(self, callsign, ssid):
        """
        Respond with a brief list of valid commands to the sender.
    
        Args:
        sender (str): The call sign of the message sender.
        """
        help_message = "Cmds: SUNRISE, ISS_LOCATION, SKGWEATHER, WEATHER?CITY, TIP, REPEATERS, BEACON"
        logging.info(f"Sending help to {callsign}-{ssid}")
        self.send_packet(callsign, ssid, f":{callsign}-{ssid}: {help_message}".encode('utf-8'))

    def send_unknown(self, callsign, ssid):
        """Respond with an unknown command message."""
        self.send_packet(callsign, ssid, f":{callsign}-{ssid}: Unknown command. Try HELP".encode('utf-8'))

    def run(self):
        """Connect and start listening for packets."""
        self.connect()
        if self.sock is None:
            logging.error("Could not connect to Direwolf. Exiting.")
            return

        while True:
            self.receive_packet()
            self.process_message_queue()

if __name__ == "__main__":
    bot = APRSBot(src_call=CALLSIGN, src_ssid=SSID)
    bot.run()
