"""
user_ban.py — Temporary User Ban System

Implements violation tracking and automatic temporary bans for users
who exceed warning/block thresholds. Uses in-memory storage with thread safety.
"""

import time
import logging
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Dict, Optional, Tuple

logger = logging.getLogger("prompt-guardian")


class UserBanManager:
    """Thread-safe user violation tracking and ban management."""
    
    def __init__(self, 
                 max_warnings: int = 5,
                 max_blocks: int = 3,
                 ban_duration_days: int = 7):
        """
        Initialize ban manager with configurable thresholds.
        
        Args:
            max_warnings: Maximum warnings before ban
            max_blocks: Maximum blocks before ban  
            ban_duration_days: Duration of temporary ban in days
        """
        self.max_warnings = max_warnings
        self.max_blocks = max_blocks
        self.ban_duration_days = ban_duration_days
        
        self._lock = Lock()
        self._users: Dict[str, Dict] = {}  # user_id -> violation data
        
    def _get_user_data(self, user_id: str) -> Dict:
        """Get or create user violation data."""
        if user_id not in self._users:
            self._users[user_id] = {
                "warning_count": 0,
                "block_count": 0,
                "ban_until": None,  # Unix timestamp
                "last_violation": None,  # Unix timestamp
                "created_at": time.time()
            }
        return self._users[user_id]
    
    def is_banned(self, user_id: str) -> Tuple[bool, Optional[int]]:
        """
        Check if user is currently banned.
        
        Args:
            user_id: Unique identifier for the user (typically IP address)
            
        Returns:
            (is_banned, seconds_remaining) where seconds_remaining is None if not banned
        """
        with self._lock:
            user_data = self._get_user_data(user_id)
            ban_until = user_data.get("ban_until")
            
            if ban_until is None:
                return False, None
                
            now = time.time()
            if now >= ban_until:
                # Ban expired - reset counters
                self._reset_user_violations(user_id)
                return False, None
                
            remaining_seconds = int(ban_until - now)
            return True, remaining_seconds
    
    def record_violation(self, user_id: str, action: str) -> Tuple[bool, Optional[int]]:
        """
        Record a policy violation and check if ban should be applied.
        
        Args:
            user_id: Unique identifier for the user
            action: Action taken ("WARN" or "BLOCK")
            
        Returns:
            (was_banned, ban_duration_seconds) where ban_duration_seconds is None if no ban
        """
        with self._lock:
            user_data = self._get_user_data(user_id)
            now = time.time()
            
            # Skip if already banned
            if user_data.get("ban_until") and now < user_data["ban_until"]:
                return True, int(user_data["ban_until"] - now)
            
            # Record violation
            user_data["last_violation"] = now
            
            if action == "WARN":
                user_data["warning_count"] += 1
                logger.info("User %s warning count: %d/%d", 
                           user_id, user_data["warning_count"], self.max_warnings)
            elif action == "BLOCK":
                user_data["block_count"] += 1
                logger.info("User %s block count: %d/%d", 
                           user_id, user_data["block_count"], self.max_blocks)
            else:
                logger.warning("Invalid action for violation tracking: %s", action)
                return False, None
            
            # Check thresholds
            should_ban = False
            ban_reason = None
            
            if user_data["warning_count"] >= self.max_warnings:
                should_ban = True
                ban_reason = f"Warning threshold exceeded ({user_data['warning_count']}/{self.max_warnings})"
            elif user_data["block_count"] >= self.max_blocks:
                should_ban = True
                ban_reason = f"Block threshold exceeded ({user_data['block_count']}/{self.max_blocks})"
            
            if should_ban:
                ban_duration_seconds = self.ban_duration_days * 24 * 60 * 60
                ban_until = now + ban_duration_seconds
                user_data["ban_until"] = ban_until
                
                ban_until_iso = datetime.fromtimestamp(ban_until, tz=timezone.utc).isoformat()
                logger.warning("User %s BANNED until %s. Reason: %s", 
                              user_id, ban_until_iso, ban_reason)
                
                return True, ban_duration_seconds
            
            return False, None
    
    def _reset_user_violations(self, user_id: str):
        """Reset violation counters for a user."""
        if user_id in self._users:
            self._users[user_id]["warning_count"] = 0
            self._users[user_id]["block_count"] = 0
            self._users[user_id]["ban_until"] = None
            logger.info("User %s violations reset after ban expiry", user_id)
    
    def get_user_status(self, user_id: str) -> Dict:
        """
        Get detailed user violation status.
        
        Returns:
            Dict with user statistics and ban status
        """
        with self._lock:
            user_data = self._get_user_data(user_id)
            now = time.time()
            
            is_banned, remaining_seconds = self.is_banned(user_id)
            
            return {
                "user_id": user_id,
                "warning_count": user_data["warning_count"],
                "block_count": user_data["block_count"],
                "max_warnings": self.max_warnings,
                "max_blocks": self.max_blocks,
                "is_banned": is_banned,
                "ban_remaining_seconds": remaining_seconds,
                "ban_until_iso": datetime.fromtimestamp(
                    user_data["ban_until"], tz=timezone.utc
                ).isoformat() if user_data["ban_until"] else None,
                "last_violation_iso": datetime.fromtimestamp(
                    user_data["last_violation"], tz=timezone.utc
                ).isoformat() if user_data["last_violation"] else None,
                "account_created_iso": datetime.fromtimestamp(
                    user_data["created_at"], tz=timezone.utc
                ).isoformat()
            }
    
    def get_all_users_summary(self) -> Dict:
        """Get summary of all users with violations."""
        with self._lock:
            active_bans = 0
            total_warnings = 0
            total_blocks = 0
            total_users = len(self._users)
            
            for user_id, user_data in self._users.items():
                is_banned, _ = self.is_banned(user_id)
                if is_banned:
                    active_bans += 1
                total_warnings += user_data["warning_count"]
                total_blocks += user_data["block_count"]
            
            return {
                "total_users": total_users,
                "active_bans": active_bans,
                "total_warnings": total_warnings,
                "total_blocks": total_blocks,
                "max_warnings": self.max_warnings,
                "max_blocks": self.max_blocks,
                "ban_duration_days": self.ban_duration_days
            }
    
    def manually_ban_user(self, user_id: str, duration_days: int = None) -> bool:
        """
        Manually ban a user for specified duration.
        
        Args:
            user_id: User to ban
            duration_days: Override default ban duration
            
        Returns:
            True if ban was applied, False if user was already banned
        """
        with self._lock:
            user_data = self._get_user_data(user_id)
            now = time.time()
            
            # Check if already banned
            if user_data.get("ban_until") and now < user_data["ban_until"]:
                return False
            
            duration = duration_days or self.ban_duration_days
            ban_duration_seconds = duration * 24 * 60 * 60
            ban_until = now + ban_duration_seconds
            user_data["ban_until"] = ban_until
            
            ban_until_iso = datetime.fromtimestamp(ban_until, tz=timezone.utc).isoformat()
            logger.warning("User %s MANUALLY BANNED until %s", user_id, ban_until_iso)
            
            return True
    
    def unban_user(self, user_id: str) -> bool:
        """
        Manually unban a user and reset their violations.
        
        Args:
            user_id: User to unban
            
        Returns:
            True if user was unbanned, False if user wasn't banned
        """
        with self._lock:
            if user_id not in self._users:
                return False
                
            user_data = self._users[user_id]
            was_banned = user_data.get("ban_until") is not None
            
            self._reset_user_violations(user_id)
            
            if was_banned:
                logger.info("User %s MANUALLY UNBANNED", user_id)
            
            return was_banned


# Global instance - will be initialized in app.py
ban_manager: Optional[UserBanManager] = None
