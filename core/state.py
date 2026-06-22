import socket
import threading
from typing import Dict
import queue
import sqlite3
from utils.constants import DB_FILE_PATH

# Network State
clients: Dict[str, socket.socket] = {}
client_metadata: Dict[str, dict] = {}
clients_lock = threading.Lock()

# Server Stats
server_stats_lock = threading.Lock()
server_processed_packets = 0
flood_counter = {}

# DB State
db_write_lock = threading.RLock()
db_conn = sqlite3.connect(DB_FILE_PATH, check_same_thread=False)
db_conn.row_factory = sqlite3.Row
db_conn.execute("PRAGMA journal_mode=WAL")
db_queue = queue.Queue(maxsize=10000)
