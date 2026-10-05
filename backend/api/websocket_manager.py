import json
import logging
import asyncio
from typing import List, Set, Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("security_agent.websocket")


class ConnectionManager:
    """
    FastAPI WebSocket ConnectionManager.
    Manages active WebSocket connections and broadcasts real-time
    Newline Delimited JSON (NDJSON) event streams to connected clients.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept incoming WebSocket connection and register with active list."""
        await websocket.accept()
        if websocket not in self.active_connections:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Remove disconnected WebSocket from active registry."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total active connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send a direct string message to a specific connection."""
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.warning(f"Failed to send personal message: {e}")

    async def send_ndjson(self, websocket: WebSocket, data: Dict[str, Any]):
        """Format payload as single-line NDJSON (JSON + newline) and send."""
        try:
            line = json.dumps(data, default=str) + "\n"
            await websocket.send_text(line)
        except Exception as e:
            logger.warning(f"Failed to send NDJSON to client: {e}")

    async def broadcast(self, message: str):
        """Broadcast a raw string (e.g. NDJSON line) to all active connections."""
        if not message.endswith("\n"):
            message += "\n"
        dead_connections = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.warning(f"Error broadcasting to client, removing: {e}")
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

    async def broadcast_ndjson(self, data: Dict[str, Any]):
        """Broadcast an event as an NDJSON line to all active connections."""
        line = json.dumps(data, default=str) + "\n"
        await self.broadcast(line)

    def get_active_count(self) -> int:
        """Return the number of connected WebSocket clients."""
        return len(self.active_connections)


# Global singleton instance
manager = ConnectionManager()
# Backward-compatible alias
NDJSONConnectionManager = ConnectionManager
ws_manager = manager
